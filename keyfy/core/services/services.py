from keyfy.core.services.db import SessionLocal
from keyfy.core.services.encryption import decrypt, derive_key, encrypt, generate_salt
from keyfy.core.services.models.models import Credential, User


def create_user(username: str, password: str):
    """
    Create a new user in the DB.
    """

    # Establish connection with DB
    session = SessionLocal()

    try:
        # Encrypt password
        auth_salt = generate_salt()
        vault_salt = generate_salt()
        hashed_pass = derive_key(password, auth_salt)

        user = User(
            username=username,
            password=hashed_pass,
            auth_salt=auth_salt,
            vault_salt=vault_salt,
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def login_user(username, password) -> tuple[int, str, bytes]:
    """
    Authenticates the user, then returns the user_id and encryption_key
    """
    session = SessionLocal()

    try:
        # Find user
        user = session.query(User).filter_by(username=username).first()
        if not user:
            raise ValueError("User not Found")

        # Verify password
        auth_salt = user.auth_salt
        password_hash = derive_key(password, auth_salt)

        if user.password != password_hash:
            raise ValueError("Try Again Password incorrect.")

        # Authenticated user. Provide encryption key
        vault_salt = user.vault_salt
        encryption_key = derive_key(password, vault_salt)

        return user.id, user.username, encryption_key

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_credential(user_id: int, vault_key: bytes, service_key: str) -> dict:
    """
    Returns a credential based in the key
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")

        creds = user.vault.get(service_key)
        if not creds:
            raise ValueError("Key not found in vault")

        decrypted_password = decrypt(vault_key, creds.password)

        return {"username": creds.username, "password": decrypted_password}

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_user_by_id(user_id: int) -> User:
    """
    Returns the user based on ID.
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        return user
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def is_username_available(username: str) -> bool:
    """
    Checks the availability of the username.
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(username=username).first()
        return not bool(user)
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_vault_keys(user_id: int) -> list:
    """
    Returns the user based on ID.
    """
    session = SessionLocal()

    try:
        # Query for username
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")

        return list(user.vault.keys())
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def add_credential(
    user_id: int,
    encryption_key: bytes,
    service_key: str,
    service_username: str,
    service_password: str,
):
    """
    Returns a User based on the passed username.
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")

        encrypted_password = encrypt(encryption_key, service_password)
        cred = Credential(
            key=service_key, username=service_username, password=encrypted_password
        )

        user.vault[service_key] = cred
        session.commit()
        session.refresh(cred)
        return cred

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def delete_credentials(user_id: int, service_key: str):
    """
    Delets a credential via key.
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")
        vault = user.vault

        if service_key in vault:
            del vault[service_key]
            session.commit()

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def main():
    pass


if __name__ == "__main__":
    main()
