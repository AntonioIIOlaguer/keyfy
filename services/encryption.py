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


def encrypt(password, plain_message):
    """
    Encrypts a message using AES-GCM and PBKDF2.
    Returns a base64-encoded byte string of: salt + iv + ciphertext.
    """

    # Generate randomness
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = get_secret_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plain_message.encode("utf-8"), None)

    return {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def decrypt(password, encoded_cipher):
    """
    Decrypts a base64-encoded AES-GCM cipher using the given password.
    """

    # Extract informatino from encoded cipher
    salt = base64.b64decode(encoded_cipher["salt"])
    iv = base64.b64decode(encoded_cipher["iv"])
    ciphertext = base64.b64decode(encoded_cipher["ciphertext"])

    # Decrypt
    key = get_secret_key(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(iv, ciphertext, None)

    return decrypted.decode("utf-8")


def get_secret_key(password, salt):
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


def get_hashed_key_and_salt(password: str) -> tuple:
    """
    Returns the key with generated salt using PBKDF2.
    """
    salt = os.urandom(SALT_LENGTH)
    hashed_key = base64.b64encode(get_secret_key(password, salt)).decode()

    return hashed_key, base64.b64encode(salt).decode()


def main():
    outputFormat = "{:<25}:{}"
    secret_key = "your_secure_key"
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
