from rich.console import Console
from rich.table import Table

from keyfy.core.integrations.logger_service import log_activity
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
        log_activity(user.id, "Register", "Created Account")

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
            log_activity(
                user.id, "Login", "Unsuccessful login attempt. Password Inorrect"
            )
            raise ValueError("Try Again Password incorrect.")

        # Authenticated user. Provide encryption key
        vault_salt = user.vault_salt
        encryption_key = derive_key(password, vault_salt)

        log_activity(user.id, "Login", "Succesffully logged in.")
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
            log_activity(
                user.id,
                "Retrieve-key",
                f"Attempted to retrieve {service_key} key. Does not exist.",
            )
            raise ValueError("Key not found in vault")

        decrypted_password = decrypt(vault_key, creds.password)

        log_activity(
            user.id, "Retrieve-key", f"Retrieved credentials for {service_key} key"
        )
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

        log_activity(user.id, "Retrieve-all-keys", "Retrieved all vault keys")
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

        log_activity(user.id, "Save-key", f"Saved credentials for {service_key} key.")
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
            log_activity(
                user.id, "Delete-key", f"Deleted credentials for {service_key} key."
            )

    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()


def show_pretty_logs(logs):
    """
    A table display for logs from the logger service.
    """
    table = Table(title="Activity Logs")
    table.add_column("Time", style="Green")
    table.add_column("Action", style="yellow")
    table.add_column("Message", style="yellow")

    for log in logs:
        time = log.get("timestamp")
        action = log.get("action")
        message = log.get("message")

        table.add_row(time, action, message)

    console = Console()
    console.print(table)


def main():
    pass


if __name__ == "__main__":
    main()
