import streamlit as st
import asyncio
import aiohttp
from mnemonic import Mnemonic
from stellar_sdk import Keypair, StrKey
import nacl.signing
import hashlib
import hmac
import struct
import unicodedata
from io import BytesIO
import fpdf
import logging
import time

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Pi Network constants
NETWORK_PASSPHRASE = "Pi Network"
PI_EXPLORER_URL = "https://api.mainnet.minepi.com/accounts/"  # Your confirmed endpoint
PI_ASSET_CODE = "native"
PI_DERIVATION_PATH = "m/44'/314159'/0'"
QUERY_DELAY = 1.0

# Derivation helpers (unchanged)
PBKDF2_ROUNDS = 2048
PBKDF2_SALT_PREFIX = "mnemonic"

def _mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    mnemonic_norm = unicodedata.normalize("NFKD", mnemonic)
    salt = PBKDF2_SALT_PREFIX + unicodedata.normalize("NFKD", passphrase)
    return hashlib.pbkdf2_hmac("sha512", mnemonic_norm.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS, dklen=64)

def _hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def _master_key(seed: bytes):
    I = _hmac_sha512(b"ed25519 seed", seed)
    return I[:32], I[32:]

def _ckd_priv_ed25519(parent_key: bytes, parent_chain: bytes, index: int):
    data = b"\x00" + parent_key + struct.pack(">L", index)
    I = _hmac_sha512(parent_chain, data)
    return I[:32], I[32:]

@st.cache_data(ttl=300)
def derive_pi_keypair(mnemonic: str, path=PI_DERIVATION_PATH):
    try:
        mnemo = Mnemonic("english")
        if not mnemo.check(mnemonic):
            return None, None, "Invalid mnemonic (BIP39 check failed)"
        word_count = len(mnemonic.split())
        if word_count not in [12, 24]:
            return None, None, f"Invalid word count: {word_count} (must be 12 or 24)"
        
        seed = _mnemonic_to_seed(mnemonic.strip())
        k, c = _master_key(seed)
        parent_k, parent_c = k, c
        for part in path.lstrip("m/").split("/"):
            if not part:
                continue
            hardened = part.endswith("'")
            idx_str = part[:-1] if hardened else part
            if not idx_str.isdigit():
                return None, None, f"Invalid path component: {part}"
            idx = int(idx_str)
            if not hardened:
                return None, None, "Pi Network requires hardened derivation."
            idx = idx + 0x80000000
            parent_k, parent_c = _ckd_priv_ed25519(parent_k, parent_c, idx)
        signing_key = nacl.signing.SigningKey(parent_k)
        verify_key = signing_key.verify_key
        secret_seed = StrKey.encode_ed25519_secret_seed(bytes(signing_key))
        public_key = StrKey.encode_ed25519_public_key(bytes(verify_key))
        logger.info(f"Derived public key: {public_key}")
        return public_key, secret_seed, None
    except Exception as e:
        logger.error(f"Derivation error: {str(e)}")
        return None, None, f"Derivation error: {str(e)}"

async def async_get_balance(public_address: str, session: aiohttp.ClientSession):
    """Query mainnet.minepi.com for available balance."""
    url = f"{PI_EXPLORER_URL}{public_address}"
    for attempt in range(3):
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    logger.info(f"Raw API response for {public_address[:10]}...: {data}")
                    balances = data.get('balances', [])
                    if not balances:
                        logger.info(f"No balances found for {public_address[:10]}...")
                        return 0.0
                    for balance_entry in balances:
                        if balance_entry.get('asset_type') == PI_ASSET_CODE:
                            balance = float(balance_entry.get('balance', '0'))
                            logger.info(f"Parsed balance for {public_address[:10]}...: {balance}")
                            return balance
                    logger.info(f"No native balance found for {public_address[:10]}...")
                    return 0.0
                else:
                    logger.warning(f"API status {resp.status} for {public_address[:10]}...")
                    await asyncio.sleep(QUERY_DELAY)
        except Exception as e:
            logger.warning(f"API query failed for {public_address[:10]}...: {str(e)}")
            await asyncio.sleep(QUERY_DELAY)
    return None

async def async_test_balance(test_address: str):
    """Async wrapper for testing a single address balance."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        balance = await async_get_balance(test_address, session)
        return balance

def export_to_pdf(qualified_results, skipped_results, filename="pi_wallets_report.pdf"):
    pdf = fpdf.FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', size=14)
    pdf.cell(200, 10, txt="Pi Network Wallet Balance Report", ln=True, align="C")
    pdf.ln(10)
    
    pdf.set_font("Arial", size=10)
    if not qualified_results and not skipped_results:
        pdf.cell(0, 8, txt="No wallets found.", ln=True)
    else:
        pdf.cell(100, 8, "Mnemonic Phrase (Full)", border=1)
        pdf.cell(30, 8, "Balance (PI)", border=1)
        pdf.cell(60, 8, "Public Address", border=1)
        pdf.ln()
        # Qualified wallets (>=2 PI)
        pdf.set_font("Arial", 'B', size=10)
        pdf.cell(0, 8, txt="Qualified Wallets (>=2 PI)", ln=True)
        pdf.set_font("Arial", size=10)
        for phrase, balance, address in qualified_results:
            pdf.multi_cell(100, 8, phrase, border=1)
            pdf.cell(30, 8, f"{balance:.2f}", border=1)
            pdf.cell(60, 8, address, border=1)
            pdf.ln()
        # Skipped wallets (<2 PI or failed)
        pdf.set_font("Arial", 'B', size=10)
        pdf.cell(0, 8, txt="Skipped Wallets (<2 PI or Failed)", ln=True)
        pdf.set_font("Arial", size=10)
        for phrase, balance, address in skipped_results:
            pdf.multi_cell(100, 8, phrase, border=1)
            pdf.cell(30, 8, f"{balance if balance is not None else 'Failed'}", border=1)
            pdf.cell(60, 8, address, border=1)
            pdf.ln()
    
    pdf_output = BytesIO()
    pdf_content = pdf.output(dest='S')
    if isinstance(pdf_content, str):
        pdf_output.write(pdf_content.encode('latin1'))
    else:
        pdf_output.write(pdf_content)  # Already bytes
    pdf_output.seek(0)
    return pdf_output, filename

# Streamlit Interface
st.title("Pi Network Wallet Balance Checker")
st.warning("**Security Note**: Local-only. Queries public explorer. Never share phrases.")

st.markdown("### Quick Test: Enter a Single Address")
test_address = st.text_input("Test Public Address (G...):", value="GCLR2XKA247JPPMXYPZEB5IQWGNUK4MBHD6NHGTLXWUWKQYS4PLJZWJO")
if test_address:
    if st.button("Test Balance Query"):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            balance = loop.run_until_complete(async_test_balance(test_address))
            st.info(f"Test Balance for {test_address}: {balance if balance is not None else 'Query Failed'} PI")
            logger.info(f"Test complete for {test_address}")
        except Exception as e:
            st.error(f"Test failed: {str(e)}")
            logger.error(f"Test failed for {test_address}: {str(e)}")

st.markdown("### Paste Your Mnemonic Phrases")
st.info("One 12- or 24-word phrase per line. Invalid skipped.")

input_text = st.text_area("Phrases:", height=200, placeholder="lemon inside club ... (full 12/24 words)")

async def process_phrases(phrases):
    qualified_results = []
    skipped_results = []
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        for i, phrase in enumerate(phrases):
            public_key, _, error = derive_pi_keypair(phrase)
            if error:
                st.warning(f"Skipping invalid phrase: {error}")
                continue
            
            balance = await async_get_balance(public_key, session)
            if balance is not None and balance >= 2:
                qualified_results.append((phrase, balance, public_key))
                st.success(f"Qualified: {phrase} | {balance:.2f} PI | {public_key}")
            else:
                skipped_results.append((phrase, balance, public_key))
                # No st.info for skipped wallets
            
            await asyncio.sleep(QUERY_DELAY)
    
    # Sort qualified by balance (descending) and skipped by balance (ascending)
    qualified_results.sort(key=lambda x: x[1], reverse=True)
    skipped_results.sort(key=lambda x: x[1] if x[1] is not None else float('inf'))
    return qualified_results, skipped_results

if st.button("Check Balances"):
    if not input_text.strip():
        st.error("Enter at least one phrase.")
    else:
        phrases = [line.strip() for line in input_text.splitlines() if line.strip()]
        if not phrases:
            st.error("No valid lines found.")
        else:
            st.info(f"Processing {len(phrases)} phrases...")
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                qualified_results, skipped_results = loop.run_until_complete(process_phrases(phrases))
                
                if qualified_results or skipped_results:
                    if qualified_results:
                        st.success(f"Found {len(qualified_results)} wallets >=2 PI!")
                        # Display qualified wallets only
                        st.markdown("### Qualified Wallets (>=2 PI)")
                        df_data = {
                            "Mnemonic Phrase (Full)": [r[0] for r in qualified_results],
                            "Balance (PI)": [f"{r[1]:.2f}" for r in qualified_results],
                            "Public Address": [r[2] for r in qualified_results]
                        }
                        st.table(df_data)
                    else:
                        st.info("No wallets >=2 PI found.")
                    # Generate PDF with both qualified and skipped
                    pdf_output, filename = export_to_pdf(qualified_results, skipped_results)
                    st.download_button("Download PDF Report", pdf_output, filename, mime="application/pdf")
                else:
                    st.info("No wallets found.")
            except Exception as e:
                st.error(f"Processing failed: {str(e)}")
                logger.error(f"Processing failed: {str(e)}")

st.markdown("---")
st.caption("Uses mainnet.minepi.com public explorer. Balances may include locked PI. Verify in Pi app.")
