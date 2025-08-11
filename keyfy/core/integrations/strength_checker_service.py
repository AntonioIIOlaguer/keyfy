import requests

from keyfy import config
from keyfy.core.integrations.service_error import PortMissingError


def check_password_strength(password) -> dict:
    """
    Returns the strength of the password as well as remarks.
    """
    payload = {"password": password}

    try:
        if not config.PASSWORD_STRENGTH_CHECKER_URL:
            raise PortMissingError
        response = requests.post(
            f"{config.PASSWORD_STRENGTH_CHECKER_URL}",
            json=payload,
            timeout=10,
        )

        response.raise_for_status()

        return response.json()
    except PortMissingError:
        print("Error: Port is missing for the password strength service.")
    except requests.exceptions.ConnectionError:
        print("Error: Service is not available (connection failed).")
    except requests.exceptions.Timeout:
        print("Error: Service is not responding (timeout).")
