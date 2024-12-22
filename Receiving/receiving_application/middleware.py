import base64
import json
import logging
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from Crypto.Cipher import AES
from hashlib import sha256, blake2b

# Initialize logger
logger = logging.getLogger(__name__)

# Shared secret key and salt (must match the Sending Application)
SECRET_KEY = b'my_secret_key_for_middleware_1234'  # 32 bytes for AES-256
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

# AES Decryption
def decrypt(data, key):
    """Decrypt data using AES-GCM."""
    try:
        data = base64.b64decode(data)
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        # Log parsed values
        logger.debug(f"Nonce (Receiving): {nonce.hex()}")
        logger.debug(f"Tag (Receiving): {tag.hex()}")
        logger.debug(f"Ciphertext (Receiving): {ciphertext.hex()}")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        raise ValueError("Invalid decryption")

# Middleware Class
class DecryptionMiddleware(MiddlewareMixin):
    def process_request(self, request):
        """Decrypt the POST data for the '/receive-message/' path."""
        if request.method == 'POST' and '/receive-message/' in request.path:
            try:
                # Ensure the request body is not empty
                if not request.body:
                    raise ValueError("Empty request body")

                # Parse JSON body
                try:
                    body = json.loads(request.body.decode('utf-8'))
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decoding failed: {str(e)}")
                    return JsonResponse({'error': 'Invalid JSON format'}, status=400)

                # Extract necessary fields
                encrypted_content = body.get('content')
                content_hash = body.get('hash')
                encryption_method = body.get('encryption_method', '')

                # Log incoming data
                logger.debug(f"Original Payload: {body}")
                logger.debug(f"Encrypted Content: {encrypted_content}")
                logger.debug(f"Hash: {content_hash}")
                logger.debug(f"Encryption Method: {encryption_method}")

                # Validate required fields
                if not encrypted_content or not isinstance(encrypted_content, str):
                    raise ValueError("Invalid or missing encrypted content")

                if not content_hash or len(content_hash) != 64:
                    raise ValueError("Invalid or missing content hash")

                if not encryption_method:
                    raise ValueError("Missing encryption method")

                # Reverse the encryption flow for decryption
                encryption_flow = encryption_method.split('-')
                encryption_flow.reverse()
                derived_key = SECRET_KEY

                for method_name in encryption_flow:
                    derive_key_func = {'sha256': derive_key_sha256, 'blake2': derive_key_blake2}.get(method_name)
                    if not derive_key_func:
                        raise ValueError(f"Unsupported encryption method: {method_name}")
                    derived_key = derive_key_func(derived_key, SALT)
                    logger.debug(f"Derived Key (Receiving) for {method_name}: {derived_key.hex()}")

                # Final derived key log
                logger.debug(f"Final Derived Key (Receiving): {derived_key.hex()}")

                # Perform decryption
                decrypted_content = decrypt(encrypted_content, derived_key)
                logger.debug(f"Decrypted Content: {decrypted_content}")

                # Validate hash
                calculated_hash = blake2b(decrypted_content.encode(), digest_size=32).hexdigest()
                logger.debug(f"Received Hash: {content_hash}")
                logger.debug(f"Calculated Hash: {calculated_hash}")
                if calculated_hash != content_hash:
                    raise ValueError("Hash mismatch")

                # Store decrypted content in request.META for use in the view
                request.META['decrypted_content'] = decrypted_content
                request.META['original_body'] = body

            except ValueError as ve:
                logger.error(f"Validation error: {ve}")
                return JsonResponse({'error': str(ve)}, status=400)
            except Exception as e:
                logger.error(f"Decryption error: {e}")
                return JsonResponse({'error': 'Decryption failed'}, status=400)
