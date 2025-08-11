import requests

from keyfy import config
from keyfy.core.integrations.service_error import PortMissingError
from keyfy.core.services.encryption import hash_sha1


def check_breached_password(password) -> dict:
    """
    Check the password against a HIBP database using SHA1 hash.
    """
    payload = {"hash_sha1": hash_sha1(password)}

    try:
        if not config.BREACHED_CHECKER_URL:
            raise PortMissingError
        response = requests.post(
            f"{config.BREACHED_CHECKER_URL}",
            json=payload,
            timeout=10,
        )
        response.raise_for_status()

        return response.json()
    except PortMissingError:
        print("Error: Port is missing for the breach checker service.")
    except requests.exceptions.ConnectionError:
        print("Error: Service is not available (connection failed).")
    except requests.exceptions.Timeout:
        print("Error: Service is not responding (timeout).")
