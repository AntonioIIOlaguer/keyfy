import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
HASH_NAME = hashes.SHA512()
IV_LENGTH = 12
ITERATION_COUNT = 65535
KEY_LENGTH = 32
SALT_LENGTH = 16


def encrypt(encryption_key: bytes, password: str) -> dict:
    """
    Encrypts a message using AES-GCM and PBKDF2.
    Returns a base64-encoded byte string of: salt + iv + ciphertext.
    """

    # Generate randomness
    iv = os.urandom(IV_LENGTH)

    aesgcm = AESGCM(encryption_key)
    ciphertext = aesgcm.encrypt(iv, password.encode("utf-8"), None)

    return {
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt(encryption_key: bytes, encoded_cipher: dict) -> str:
    """
    Decrypts a base64-encoded AES-GCM cipher using the given password.
    """

    # Extract informatino from encoded cipher
    iv = base64.b64decode(encoded_cipher["iv"])
    ciphertext = base64.b64decode(encoded_cipher["ciphertext"])

    # Decrypt
    aesgcm = AESGCM(encryption_key)
    decrypted = aesgcm.decrypt(iv, ciphertext, None)

    return decrypted.decode("utf-8")


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a key from the password and salt using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=HASH_NAME,
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATION_COUNT,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def generate_salt() -> bytes:
    """
    Returns a 16byte generated salt.
    """
    return os.urandom(SALT_LENGTH)


def main():
    pass


# Test the implementation
if __name__ == "__main__":
    main()
