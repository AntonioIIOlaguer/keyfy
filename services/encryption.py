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


def encrypt(encryption_key, password):
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


def decrypt(encryption_key, encoded_cipher):
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


def get_secret_key(password: str, salt: bytes) -> str:
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
    return base64.b64encode(kdf.derive(password.encode())).decode()


def get_hashed_key_and_salt(password: str) -> tuple:
    """
    Returns the key with generated salt using PBKDF2.
    """
    salt = os.urandom(SALT_LENGTH)
    hashed_key = get_secret_key(password, salt)

    return hashed_key, base64.b64encode(salt).decode()


def main():
    outputFormat = "{:<25}:{}"
    secret_key, salt = get_hashed_key_and_salt("your_secure_key")
    secret_key = base64.b64decode(secret_key)
    plain_text = "Your_plain_text"

    print("------ AES-GCM Encryption ------")
    cipher_text = encrypt(secret_key, plain_text)
    print(outputFormat.format("encryption input", plain_text))
    print(outputFormat.format("encryption output", cipher_text))

    decrypted_text = decrypt(secret_key, cipher_text)

    print("\n------ AES-GCM Decryption ------")
    print(outputFormat.format("decryption input", cipher_text))
    print(outputFormat.format("decryption output", decrypted_text))


# Test the implementation
if __name__ == "__main__":
    main()
