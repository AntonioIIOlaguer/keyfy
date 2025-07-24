from services.db import SessionLocal
from services.encryption import decrypt, derive_key, encrypt, generate_salt
from services.models.models import Credential, User


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


def login_user(username, password) -> tuple[int, bytes]:
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
        encryption_key = derive_key("mypass", vault_salt)

        return user.id, encryption_key

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def get_credential(user_id: int, key: str, vault_key: bytes) -> dict:
    """
    Returns a credential based in the key
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")

        creds = user.vault[key]

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
    user_id: int, encryption_key: bytes, key: str, service_username: str, password: str
):
    """
    Returns a User based on the passed username.
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")

        encrypted_password = encrypt(encryption_key, password)
        cred = Credential(
            key=key, username=service_username, password=encrypted_password
        )

        user.vault[key] = cred
        session.commit()
        session.refresh(cred)
        return cred

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def delete_key(user_id: int, key: str):
    """
    Delets a credential via key.
    """
    session = SessionLocal()

    try:
        user = session.query(User).filter_by(id=user_id).first()
        if not user:
            raise ValueError("User not Found")
        vault = user.vault

        if key in vault:
            del vault[key]
            session.commit()

        return

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def main():
    """
    Test implementation
    """
    # user = create_user("test_person", "mypass")
    user, vault_key = login_user("test_person", "mypass")

    print(add_credential(1, vault_key, "what", "icy3", "passilyo").password)

    # print(delete_key(1, "face"))

    print(get_vault_keys(user))
    print(get_credential(user, "what", vault_key))


if __name__ == "__main__":
    main()
