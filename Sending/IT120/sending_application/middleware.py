import base64
import random
from django.utils.deprecation import MiddlewareMixin
from Crypto.Cipher import AES
from hashlib import sha256, pbkdf2_hmac, blake2b
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json
import logging

# Initialize logger
logger = logging.getLogger(__name__)

# Secret key and salt
SECRET_KEY = b'my_secret_key_for_middleware_1234'  # Must be 32 bytes for AES-256
SALT = b'my_salt_value_1234'

# Encryption Methods
def derive_key_sha256(password, salt):
    """Derive a cryptographic key using SHA-256."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    return sha256(password + salt).digest()

def derive_key_argon2(password, salt):
    """Derive a cryptographic key using Argon2."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=8, hash_len=32)
    combined = password + salt
    return ph.hash(combined)[:32].encode('utf-8')

def derive_key_blake2(password, salt):
    """Derive a cryptographic key using BLAKE2."""
    if isinstance(password, str):
        password = password.encode('utf-8')
    if isinstance(salt, str):
        salt = salt.encode('utf-8')
    h = blake2b(digest_size=32)
    h.update(password + salt)
    return h.digest()

# AES Encryption
def encrypt(data, key):
    """Encrypt data using AES-GCM."""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

# AES Decryption
def decrypt(encrypted_data, key):
    """Decrypt data using AES-GCM."""
    data = base64.b64decode(encrypted_data)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# BLAKE2 Hashing
def blake2_hash(data):
    """Generate a BLAKE2 hash for the given data."""
    h = blake2b(digest_size=32)
    h.update(data.encode())
    return h.hexdigest()

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
                
                # Randomly select an encryption method
                encryption_methods = [
                    ('sha256', derive_key_sha256),
                    ('argon2', derive_key_argon2),
                    ('blake2', derive_key_blake2),
                ]
                selected_method, derive_key_func = random.choice(encryption_methods)

                # Derive key and encrypt content
                derived_key = derive_key_func(SECRET_KEY, SALT)
                encrypted_content = encrypt(content, derived_key)
                hashed_content = blake2_hash(content)  # Add integrity check with BLAKE2

                # Create a mutable copy of POST data
                post_data = request.POST.copy()
                post_data['content'] = encrypted_content
                post_data['hash'] = hashed_content
                post_data['encryption_method'] = selected_method  # Store selected method for decryption

                # Replace the original POST data with the modified copy
                request.POST = post_data
            except Exception as e:
                logger.error(f"Error during request encryption: {str(e)}")

    def process_response(self, request, response):
        """Decrypt content for the '/receive-message/' path."""
        if '/receive-message/' in request.path and response.status_code == 200:
            try:
                # Attempt to parse the response content as JSON
                data = json.loads(response.content)
                encrypted_content = data.get('content', '')
                selected_method = data.get('encryption_method', '')

                if not encrypted_content or not selected_method:
                    logger.warning("No encrypted content or encryption method found in the response.")
                    return response

                # Select the appropriate decryption method
                derive_key_func = {
                    'sha256': derive_key_sha256,
                    'argon2': derive_key_argon2,
                    'blake2': derive_key_blake2,
                }.get(selected_method)

                if not derive_key_func:
                    raise ValueError("Invalid encryption method specified.")

                # Decrypt the content
                derived_key = derive_key_func(SECRET_KEY, SALT)
                decrypted_content = decrypt(encrypted_content, derived_key)
                data['content'] = decrypted_content
                response.content = json.dumps(data).encode()
            except json.JSONDecodeError:
                logger.error("Failed to decode JSON response content.")
                response.content = json.dumps({'error': 'Invalid response format'}).encode()
            except Exception as e:
                logger.error(f"Error during response decryption: {str(e)}")
                response.content = json.dumps({'error': 'Failed to decrypt content'}).encode()

        # Add No-Cache Headers for Restricted Pages
        if request.user.is_authenticated and response.status_code == 200:
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'

        return response
