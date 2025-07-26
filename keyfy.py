import os
import sys
import time

import questionary
from sqlalchemy import try_cast

from assets.banner import KEYFY_ASCII
from services.services import (
    add_credential,
    delete_credentials,
    get_credential,
    get_vault_keys,
    login_user,
)

session = {}


def clear_screen():
    """
    Conditionally clear the terminal based on os.
    """
    os.system("cls" if os.name == "nt" else "clear")


def login_view():
    """
    Login prompt for the application.
    """
    clear_screen()
    print(KEYFY_ASCII)
    print("Welcome to Keyfy! Your Personal password manager.")
    print("Store your credentials safely and gain access to it whenever you want.\n")
    print(
        "Please login to access your vault or register by running this command keyfy -init."
    )

    username = questionary.text("Enter your username: ").ask()
    password = questionary.password("Enter your password: ").ask()

    # Authenticate user
    try:
        user_id, username, vault_key = login_user(username, password)

        session["user_id"] = user_id
        session["username"] = username
        session["vault_key"] = vault_key
        main_menu()
    except Exception as e:
        print(e)
        choice = questionary.select(
            f"{e}. Try again?:", choices=["Try again", "Exit"]
        ).ask()
        handle_relogin_choice(choice)


def main_menu():
    """
    Main UI of the keyfy app
    """
    clear_screen()
    print(KEYFY_ASCII)
    print(f"Welcome {session.get("username")}! What do you want to do? \n")
    choice = questionary.select(
        "Main Menu:",
        choices=[
            "🔐 Store key",
            "🔎 Retrieve by key",
            "📜 Show all keys",
            "❌ Delete a key",
            "🆘 Help",
            "Exit app",
        ],
    ).ask()

    handle_main_menu_choice(choice)


def handle_main_menu_choice(choice):
    """
    Routes the menu option of the UI app
    """
    if choice == "🔐 Store key":
        store_key_view()
    elif choice == "🔎 Retrieve by key":
        retrieve_key_view()
    elif choice == "📜 Show all keys":
        show_all_keys_view()
    elif choice == "❌ Delete a key":
        delete_key_view()
    elif choice == "🆘 Help":
        help_view()
    elif choice == "Exit app":
        exit_app()
    else:
        main_menu()


def handle_relogin_choice(choice):
    """
    Relogin prompt.
    """
    if choice == "Exit":
        exit_app()
    elif choice == "Try again":
        login_view()


def store_key_view():
    """
    A menu option for saving keys in the vault.
    """
    clear_screen()
    print(KEYFY_ASCII)
    print("Save your credentials here! \n")

    key = questionary.text("Enter key name:").ask()
    username = questionary.text("Username:").ask()
    password = questionary.password("Password:").ask()

    try:
        user_id = session.get("user_id")
        vault_key = session.get("vault_key")

        if not user_id or not vault_key:
            raise ValueError("Not authenticated")

        add_credential(user_id, vault_key, key, username, password)
        print("Key Saved")
        time.sleep(1)
    except Exception as e:
        print(e)
        print("Please try again.")
        time.sleep(1)
    finally:
        main_menu()


def retrieve_key_view():
    """
    Menu to retrieve the user input key
    """
    clear_screen()
    print(KEYFY_ASCII)
    print("Retrieve your key! \n")

    key = questionary.text("Enter key name: ").ask()

    try:
        creds = retrieve_key(key)
        print(creds)

        # Reprompt if requested
        confirm = questionary.confirm("Get another key?").ask()
        if confirm:
            retrieve_key_view()
        main_menu()

    except Exception as e:
        print(e)
        try_again = questionary.confirm("Try again?").ask()

        if try_again:
            retrieve_key_view()
        main_menu()


def delete_key_view():
    """
    Menu to delete the user input key
    """
    clear_screen()
    print(KEYFY_ASCII)
    print("Delete your key from the vault. \n")

    key = questionary.text("Enter key to delete: ").ask()

    try:
        delete_key(key)

        print(f"Successfully deleted {key}.")

        # Reprompt if requested
        confirm = questionary.confirm("Delete another key?").ask()
        if confirm:
            delete_key_view()
        main_menu()

    except Exception as e:
        print(e)
        try_again = questionary.confirm("Try again?").ask()

        if try_again:
            delete_key_view()
        main_menu()


def show_all_keys_view():
    """
    A menu to show all vault keys.
    """
    clear_screen()
    print(KEYFY_ASCII)
    print("Here are your keys! \n")

    try:
        user_id = session.get("user_id")
        if not user_id:
            raise ValueError("Not authenticated")

        vault_keys = get_vault_keys(user_id)
        vault_keys.append("Back to menu")

        choice = questionary.select(
            "Keys: ",
            choices=vault_keys,
        ).ask()

        print(choice)
        handle_credential_choice(choice)
    except Exception as e:
        print(e)
        print("Please try again.")
        time.sleep(1)


def help_view():
    """
    Displays the features of the application and how to interact with it.
    """
    clear_screen()
    print(KEYFY_ASCII)

    print(
        "Store Key - Uses a key to store your username and password. Passwords are encrypted using AES-GCM."
    )
    print("Retrieve by key - Return the user's credentials based on the key.")
    print("Delete a key - Deletes all credentials associated by with the key")
    print("Show all keys - Shows all keys stored by the user.")

    questionary.confirm("Back to menu?").ask()
    main_menu()


def handle_credential_choice(choice):
    """
    Display selected credential in the vault.
    """
    if choice == "Back to menu":
        main_menu()
    else:
        try:
            operation = questionary.select(
                "What do you want to do with the key?", choices=["Retrieve", "Delete"]
            ).ask()

            if operation == "Retrieve":
                creds = retrieve_key(choice)
                print(creds)
            elif operation == "Delete":
                deleted = delete_key(choice)
                if deleted:
                    print(f"Succesfully deleted {choice}.")
                else:
                    print(f"{choice} not deleted")

            # Reprompt
            confirm = questionary.confirm("Show all keys again?").ask()
            if confirm:
                show_all_keys_view()
            main_menu()

        except Exception as e:
            print(e)
            print("Please try again.")
            time.sleep(1)


def retrieve_key(key):
    """
    Checks for authenticated user then get the credentials through the decrpytion process.
    """
    try:
        user_id = session.get("user_id")
        vault_key = session.get("vault_key")

        if not user_id or not vault_key:
            raise ValueError("Not authenticated")

        return get_credential(user_id, vault_key, key)
    except Exception as e:
        raise e


def delete_key(key: str) -> bool:
    """
    Check for authenticated user then delete the credentials in the vault. Returns a bool for confirmed operations
    """

    try:
        user_id = session.get("user_id")

        if not user_id:
            raise ValueError("Not authenticated")

        # Confirm deletion
        confirm = questionary.confirm(
            "\nThis operation cannot be undone and the credentials will be unrecoverable. Are you sure you want to do this? "
        ).ask()

        if confirm:
            delete_credentials(user_id, key)
            return True
        return False

    except Exception as e:
        raise e


def exit_app():
    """
    Confirmation view for exiting the app.
    """
    confirmed = questionary.confirm("Are you sure you want to exit?").ask()
    if confirmed:
        print("👋 Goodbye!")
        sys.exit(0)
    else:
        main_menu()


def run_script_mode(arg: str):
    if arg == "view-items":
        print("📄 Script mode: Viewing items")
        print("Item A\nItem B")
    elif arg == "settings":
        print("⚙️ Script mode: Showing settings")
        print("Notifications: ON\nTheme: Default")
    elif arg == "exit":
        print("👋 Exiting...")
    else:
        print(f"❓ Unknown command: {arg}")
        print("Available commands: view-items, settings, exit")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run_script_mode(sys.argv[1])
    else:
        login_view()
