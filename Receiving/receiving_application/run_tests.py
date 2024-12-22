import base64
from Crypto.Cipher import AES
from hashlib import sha256, blake2b
import logging

# Logging Setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Secret Key and Salt (must match middleware.py)
SECRET_KEY = b'my_secret_key_for_middleware_1234'
SALT = b'my_salt_value_1234'

# Key Derivation Functions
def derive_key_sha256(password, salt):
    """Derive key using SHA-256."""
    return sha256(password + salt).digest()

def derive_key_blake2(password, salt):
    """Derive key using BLAKE2."""
    h = blake2b(digest_size=32)
    h.update(password + salt)
    return h.digest()

# Static Decryption Test
def static_decryption_test():
    logger.info("Starting Static Decryption Test...")

    try:
        # Use values from the encryption test
        encrypted_content = "B/wKyYP58dJHX03ugpj2yKeIXYPl1/+n4FoneS7LHxJ5pZL30+FmHFRAtXv7aMt19tp/"
        nonce = bytes.fromhex("07fc0ac983f9f1d2475f4dee8298f6c8")
        tag = bytes.fromhex("a7885d83e5d7ffa7e05a27792ecb1f12")
        ciphertext = bytes.fromhex("79a592f7d3e1661c5440b57bfb68cb75f6da7f")
        encryption_method = "sha256-blake2"

        # Log input components
        logger.debug(f"Nonce: {nonce.hex()}")
        logger.debug(f"Tag: {tag.hex()}")
        logger.debug(f"Ciphertext: {ciphertext.hex()}")

        # Derived Key
        derived_key = SECRET_KEY
        logger.debug(f"Initial Derived Key: {derived_key.hex()}")

        for method in encryption_method.split('-')[::-1]:
            derive_key_func = {'sha256': derive_key_sha256, 'blake2': derive_key_blake2}.get(method)
            derived_key = derive_key_func(derived_key, SALT)
            logger.debug(f"Derived Key after {method}: {derived_key.hex()}")

        # Decrypt Content
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        decrypted_content = cipher.decrypt_and_verify(ciphertext, tag).decode()
        logger.info(f"Decrypted Content: {decrypted_content}")

    except Exception as e:
        logger.error(f"Static Decryption Test Failed: {e}")

# Static Encryption Test
def static_encryption_test():
    logger.info("Starting Static Encryption Test...")

    try:
        # Plaintext
        plaintext = "Static test content"

        # Derived Key
        derived_key = SECRET_KEY
        for method in ["blake2", "sha256"]:
            derive_key_func = {'sha256': derive_key_sha256, 'blake2': derive_key_blake2}.get(method)
            derived_key = derive_key_func(derived_key, SALT)
            logger.debug(f"Derived Key after {method}: {derived_key.hex()}")

        # Encrypt Content
        cipher = AES.new(derived_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
        encrypted_content = base64.b64encode(cipher.nonce + tag + ciphertext).decode()

        logger.info(f"Encrypted Content: {encrypted_content}")
        logger.debug(f"Nonce: {cipher.nonce.hex()}")
        logger.debug(f"Tag: {tag.hex()}")
        logger.debug(f"Ciphertext: {ciphertext.hex()}")

    except Exception as e:
        logger.error(f"Static Encryption Test Failed: {e}")

# Key Derivation Test
def test_key_derivation():
    logger.info("Starting Key Derivation Test...")

    try:
        derived_key = SECRET_KEY
        logger.debug(f"Initial Derived Key: {derived_key.hex()}")

        derived_key = derive_key_blake2(derived_key, SALT)
        logger.debug(f"Derived Key after blake2: {derived_key.hex()}")

        derived_key = derive_key_sha256(derived_key, SALT)
        logger.debug(f"Derived Key after sha256: {derived_key.hex()}")

    except Exception as e:
        logger.error(f"Key Derivation Test Failed: {e}")

if __name__ == "__main__":
    logger.info("Running Tests...\n")

    # Run Static Encryption Test
    static_encryption_test()

    # Run Static Decryption Test
    static_decryption_test()

    # Run Key Derivation Test
    test_key_derivation()

    logger.info("\nTests Completed.")
