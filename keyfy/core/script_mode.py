import click

from keyfy.core.integrations.logger_service import retrieve_user_log
from keyfy.core.integrations.password_generator_service import generate_password
from keyfy.core.interactive_mode import landing_page
from keyfy.core.services.services import (
    add_credential,
    create_user,
    delete_credentials,
    get_credential,
    get_vault_keys,
    is_username_available,
    login_user,
)


@click.group()
def cli():
    """Keyfy Password Manager CLI (Script Mode)"""
    pass


@cli.command()
def interactive():
    """Launch interactive mode"""
    landing_page()


@cli.command()
@click.argument("username")
@click.argument("password")
def register(username, password):
    """Register a new user"""
    if not is_username_available(username):
        click.echo("Username already taken.")
        return
    create_user(username, password)
    click.echo("User '{username}' created.")


@cli.command()
@click.argument("username")
@click.argument("password")
def all_keys(username, password):
    """List keys in your vault"""
    try:
        user_id, _, encryption_key = login_user(username, password)
        keys = get_vault_keys(user_id)
        for k in keys:
            click.echo(k)
    except Exception as e:
        click.echo(e)


@cli.command()
@click.argument("username")
@click.argument("password")
@click.argument("service_key")
def get(username, password, service_key):
    """Retrieve credentials using a key"""
    try:
        user_id, _, encryption_key = login_user(username, password)
        creds = get_credential(user_id, encryption_key, service_key)
        click.echo(creds)
    except Exception as e:
        click.echo(e)


@cli.command()
@click.argument("username")
@click.argument("password")
@click.argument("service_key")
@click.argument("service_username")
@click.argument("service_password")
def store(username, password, service_key, service_username, service_password):
    """Store new credentials"""
    try:
        user_id, _, encryption_key = login_user(username, password)
        add_credential(
            user_id, encryption_key, service_key, service_username, service_password
        )
        click.echo(f"Successfully  saved credentials for '{service_key}'!")
    except Exception as e:
        click.echo(e)


@cli.command()
@click.argument("username")
@click.argument("password")
@click.argument("service_key")
@click.argument("service_username")
@click.option(
    "--strength",
    type=click.Choice(["PIN", "Custom", "Medium", "Strong"], case_sensitive=False),
    default="Strong",
    help="Password strength type",
)
@click.option(
    "--length",
    type=int,
    default=None,
    help="Length of the password",
)
@click.option(
    "--symbols",
    type=bool,
    default=False,
    help="Presence of symbols",
)
def store_gen_pass(
    username, password, service_key, service_username, strength, length, symbols
):
    """Store credentials with a generated password"""
    try:
        user_id, _, encryption_key = login_user(username, password)

        generated_password = generate_password(strength, length, symbols)
        click.echo(f"Generated Password: {generated_password}")

        add_credential(
            user_id, encryption_key, service_key, service_username, generated_password
        )

        click.echo(f"Successfully  saved credentials for '{service_key}'!")
    except Exception as e:
        click.echo(e)


@cli.command()
@click.option(
    "--strength",
    type=click.Choice(["PIN", "Custom", "Medium", "Strong"], case_sensitive=False),
    default="Strong",
    help="Password strength type",
)
@click.option(
    "--length",
    type=int,
    default=None,
    help="Length of the password",
)
@click.option(
    "--symbols",
    type=bool,
    default=False,
    help="Presence of symbols",
)
def gen_pass(strength: str, length: int | None, symbols: bool):
    """
    Generate password:

    Strength: str -> PIN, Medium, Strong, Custom
    length: int <Optional> -> PIN(4-6), Medium(6-12), Strong(8-20), Custom(1-64)
    symbols: Bool -> True or False
    """

    try:
        generated_password = generate_password(strength, length, symbols)
        click.echo(generated_password)
    except Exception as e:
        click.echo(e)


@cli.command()
@click.argument("username")
@click.argument("password")
@click.argument("service_key")
def remove(username, password, service_key):
    """Remove credentials for a service"""

    try:
        user_id, _, encryption_key = login_user(username, password)
        delete_credentials(user_id, service_key)
        click.echo(f"Deleted credentials for '{service_key}'")
    except Exception as e:
        click.echo(e)


@cli.command()
@click.argument("username")
def show_logs(username):
    """Shows activity log of user"""

    try:
        user_id, _, encryption_key = login_user(username, password)
        click.echo(retrieve_user_log(user_id))
    except Exception as e:
        click.echo(e)


if __name__ == "__main__":
    cli()
