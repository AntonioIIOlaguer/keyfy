import click

from src.services.db import SessionLocal
from src.services.encryption import decrypt
from src.services.services import (
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
    """Password Manager CLI (Script Mode)"""
    pass


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
def retrieve(username, password, service_key):
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
        click.echo(f"Saved credentials for '{service_key}'")
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


if __name__ == "__main__":
    cli()
