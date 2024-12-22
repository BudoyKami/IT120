import base64
import json
import random
from django.utils.deprecation import MiddlewareMixin
from Crypto.Cipher import AES
from hashlib import sha256, blake2b
import logging

# Initialize logger
logger = logging.getLogger(__name__)

# Secret key and salt
SECRET_KEY = b'my_secret_key_for_middleware_1234'  # Must be 32 bytes for AES-256
SALT = b'my_salt_value_1234'

# Key Derivation Methods
def derive_key_sha256(password, salt):
    """Derive a cryptographic key using SHA-256."""
    return sha256(password + salt).digest()

def derive_key_blake2(password, salt):
    """Derive a cryptographic key using BLAKE2."""
    h = blake2b(digest_size=32)
    h.update(password + salt)
    return h.digest()

# AES Encryption
def encrypt(data, key):
    """Encrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    logger.debug(f"Nonce (Sending): {cipher.nonce.hex()}")
    logger.debug(f"Tag (Sending): {tag.hex()}")
    logger.debug(f"Ciphertext (Sending): {ciphertext.hex()}")
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# Middleware
class EncryptionMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """Encrypt POST data for the '/send-message/' path."""
        if request.method == 'POST' and '/send-message/' in request.path:
            try:
                content = request.POST.get('content', '')

                if not content:
                    logger.warning("No content provided in the POST request.")
                    return

                # Define encryption methods
                encryption_methods = [('sha256', derive_key_sha256), ('blake2', derive_key_blake2)]

                # Shuffle or fix the encryption flow for testing
                random.shuffle(encryption_methods)  # Optional: Fix if needed for consistency
                encryption_flow = []
                derived_key = SECRET_KEY

                # Apply the encryption methods
                for method_name, derive_key_func in encryption_methods:
                    encryption_flow.append(method_name)
                    derived_key = derive_key_func(derived_key, SALT)

                # Log derived keys and encryption flow
                logger.debug(f"Final Derived Key (Sending): {derived_key.hex()}")
                logger.debug(f"Encryption Flow: {'-'.join(encryption_flow)}")

                # Encrypt the content
                encrypted_content = encrypt(content, derived_key)

                # Generate hash for integrity
                hashed_content = blake2b(content.encode(), digest_size=32).hexdigest()
                logger.debug(f"Generated Hash: {hashed_content}")

                # Update POST data with encrypted values
                post_data = request.POST.copy()
                post_data['content'] = encrypted_content
                post_data['hash'] = hashed_content
                post_data['encryption_method'] = '-'.join(encryption_flow)
                request.POST = post_data

                logger.debug(f"Modified POST Data: {request.POST}")

            except Exception as e:
                logger.error(f"Error during request encryption: {str(e)}")

    def process_response(self, request, response):
        """Handle response decryption for '/receive-message/' path."""
        if '/receive-message/' in request.path and response.status_code == 200:
            try:
                # Ensure the response is JSON
                if not response.get('Content-Type', '').startswith('application/json'):
                    logger.warning("Response is not JSON. Skipping decryption.")
                    return response

                # Parse the response content
                data = json.loads(response.content)
                encrypted_content = data.get('content', '')
                encryption_method = data.get('encryption_method', '')

                if not encrypted_content or not encryption_method:
                    logger.warning("No encrypted content or encryption method found.")
                    return response

                # Reconstruct the derived key
                methods = encryption_method.split('-')
                derived_key = SECRET_KEY
                for method in methods:
                    derive_key_func = {'sha256': derive_key_sha256, 'blake2': derive_key_blake2}.get(method)
                    if not derive_key_func:
                        raise ValueError(f"Unsupported encryption method: {method}")
                    derived_key = derive_key_func(derived_key, SALT)

                # Decrypt the content
                decrypted_content = encrypt(encrypted_content, derived_key)
                data['content'] = decrypted_content

                # Replace the response content with decrypted data
                response.content = json.dumps(data).encode()

            except Exception as e:
                logger.error(f"Error during response decryption: {str(e)}")
                response.content = json.dumps({'error': 'Decryption failed'}).encode()

        return response
