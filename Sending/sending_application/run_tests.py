import base64
from Crypto.Cipher import AES
from hashlib import sha256, blake2b
import logging

# Import the encryption functions from the middleware
from middleware import derive_key_sha256, derive_key_blake2, encrypt, decrypt, EncryptionMiddleware

# Logging Setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants for Testing
SECRET_KEY = b'my_secret_key_for_middleware_1234'
SALT = b'my_salt_value_1234'

class MockRequest:
    """Mock a Django request object."""
    def __init__(self, method, path, post_data):
        self.method = method
        self.path = path
        self.POST = post_data

def static_encryption_test():
    """Test the encryption logic with static inputs."""
    logger.info("Starting Static Encryption Test...")
    try:
        # Test data
        plaintext = "Static test content"

        # Key Derivation
        derived_key = SECRET_KEY
        for method in ['blake2', 'sha256']:  # Fixed order for consistency
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

        return encrypted_content, cipher.nonce, tag, ciphertext

    except Exception as e:
        logger.error(f"Static Encryption Test Failed: {e}")

def static_decryption_test(encrypted_content, nonce, tag, ciphertext):
    """Test the decryption logic using static outputs from the encryption test."""
    logger.info("Starting Static Decryption Test...")
    try:
        # Key Derivation
        derived_key = SECRET_KEY
        for method in ['blake2', 'sha256']:  # Fixed order for consistency
            derive_key_func = {'sha256': derive_key_sha256, 'blake2': derive_key_blake2}.get(method)
            derived_key = derive_key_func(derived_key, SALT)
            logger.debug(f"Derived Key after {method}: {derived_key.hex()}")

        # Decrypt Content
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        decrypted_content = cipher.decrypt_and_verify(ciphertext, tag).decode()

        logger.info(f"Decrypted Content: {decrypted_content}")

    except Exception as e:
        logger.error(f"Static Decryption Test Failed: {e}")

def simulate_middleware_process_request():
    """Simulate the process_request method in the middleware."""
    logger.info("Simulating Middleware process_request...")
    try:
        # Simulated POST data
        post_data = {'content': 'Test message from middleware'}
        request = MockRequest(method='POST', path='/send-message/', post_data=post_data)

        # Middleware Simulation
        middleware = EncryptionMiddleware(lambda x: x)  # Mock get_response
        middleware.process_request(request)

        logger.debug(f"Modified POST Data: {request.POST}")

    except Exception as e:
        logger.error(f"Middleware Simulation Failed: {e}")

if __name__ == "__main__":
    logger.info("Running Tests...\n")

    # Test Encryption
    encrypted_content, nonce, tag, ciphertext = static_encryption_test()

    # Test Decryption
    if encrypted_content and nonce and tag and ciphertext:
        static_decryption_test(encrypted_content, nonce, tag, ciphertext)

    # Simulate Middleware
    simulate_middleware_process_request()

    logger.info("\nTests Completed.")
