import base64
from hashlib import sha256, blake2b
from argon2 import PasswordHasher

# Shared constants
SECRET_KEY = b'my_secret_key_for_middleware_1234'
SALT = b'my_salt_value_1234'

# Key Derivation Methods
def derive_key_sha256(password, salt):
    return sha256(password + salt).digest()

def derive_key_argon2(password, salt):
    ph = PasswordHasher(time_cost=2, memory_cost=51200, parallelism=8, hash_len=32)
    return ph.hash(password + salt)[:32].encode()

def derive_key_blake2(password, salt):
    h = blake2b(digest_size=32)
    h.update(password + salt)
    return h.digest()

# Test the derived keys
def test_key_derivation():
    sha256_key = derive_key_sha256(SECRET_KEY, SALT)
    argon2_key = derive_key_argon2(SECRET_KEY, SALT)
    blake2_key = derive_key_blake2(SECRET_KEY, SALT)

    print(f"SHA-256 Key: {base64.b64encode(sha256_key).decode()}")
    print(f"Argon2 Key: {base64.b64encode(argon2_key).decode()}")
    print(f"BLAKE2 Key: {base64.b64encode(blake2_key).decode()}")

if __name__ == "__main__":
    test_key_derivation()
