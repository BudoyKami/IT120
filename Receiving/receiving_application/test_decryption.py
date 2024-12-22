import base64
from Crypto.Cipher import AES
from hashlib import blake2b

# Constants (replace with actual values from logs)
SECRET_KEY = b'my_secret_key_for_middleware_1234'
SALT = b'my_salt_value_1234'
ENCRYPTED_CONTENT = "OhqeeeP7AqSvKBgNrG+IshkbvRyU8bXC39eZ9qpwIbhfa0byVCWJoA=="  # Replace with logged content
ENCRYPTION_FLOW = ['sha256', 'argon2', 'blake2']  # Replace with actual flow
NONCE = bytes.fromhex("3a1a9e79e3fb02a4af28180dac6f88b2")  # Replace with logged nonce
TAG = bytes.fromhex("191bbd1c94f1b5c2dfd799f6aa7021b8")  # Replace with logged tag

# Key Derivation Functions
def derive_key_sha256(password, salt):
    from hashlib import sha256
    return sha256(password + salt).digest()

def derive_key_argon2(password, salt):
    from argon2 import PasswordHasher
    ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=8, hash_len=32)
    return ph.hash(password + salt)[:32].encode()

def derive_key_blake2(password, salt):
    from hashlib import blake2b
    h = blake2b(digest_size=32)
    h.update(password + salt)
    return h.digest()

# Reverse encryption flow and derive key
def get_derived_key(flow, key, salt):
    flow.reverse()
    for method in flow:
        if method == "sha256":
            key = derive_key_sha256(key, salt)
        elif method == "argon2":
            key = derive_key_argon2(key, salt)
        elif method == "blake2":
            key = derive_key_blake2(key, salt)
        else:
            raise ValueError(f"Unknown encryption method: {method}")
    return key

# Decrypt content
def decrypt_content(encrypted_content, key, nonce, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(base64.b64decode(encrypted_content)[32:], tag)
    return decrypted_content.decode()

if __name__ == "__main__":
    derived_key = get_derived_key(ENCRYPTION_FLOW, SECRET_KEY, SALT)
    print(f"Derived Key: {base64.b64encode(derived_key).decode()}")
    
    decrypted_content = decrypt_content(ENCRYPTED_CONTENT, derived_key, NONCE, TAG)
    print(f"Decrypted Content: {decrypted_content}")


# Validate hash
def validate_hash(content, original_hash):
    calculated_hash = blake2b(content.encode(), digest_size=32).hexdigest()
    print(f"Calculated Hash: {calculated_hash}")
    print(f"Original Hash: {original_hash}")
    return calculated_hash == original_hash

if __name__ == "__main__":
    # Existing decryption logic here...

    original_hash = "d92c58808c6b267c8381c3cb4e9e7d057cf66afcbda0b41e0fe54ba62016b4bf"  # Replace with logged hash
    is_valid = validate_hash(decrypted_content, original_hash)
    print(f"Hash Validation: {'Passed' if is_valid else 'Failed'}")