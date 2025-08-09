import requests

from keyfy import config
from keyfy.core.integrations.service_error import PortMissingError


def log_activity(user_id: int, action: str, message: str) -> dict:
    """
    Logs the activity of a user using a activity logger microservices.
    """
    payload = {"action": action, "message": message}

    try:
        if not config.ACTIVITY_LOGGER_URL:
            raise PortMissingError
        response = requests.post(
            f"{config.ACTIVITY_LOGGER_URL}/{user_id}",
            json=payload,
            timeout=10,
        )
        response.raise_for_status()

        return response.json()
    except PortMissingError:
        print("Error: Port is missing for the logger service.")
    except requests.exceptions.ConnectionError:
        print("Error: Service is not available (connection failed).")
    except requests.exceptions.Timeout:
        print("Error: Service is not responding (timeout).")


def retrieve_user_log(user_id: int) -> list:
    """
    Retrieve all activity logs of the user.
    """

    try:
        if not config.ACTIVITY_LOGGER_URL:
            raise PortMissingError

        response = requests.get(f"{config.ACTIVITY_LOGGER_URL}/{user_id}", timeout=5)
        response.raise_for_status()

        return response.json()
    except PortMissingError:
        print("Error: Port is missing for the logger service.")
    except requests.exceptions.ConnectionError:
        print("Error: Service is not available (connection failed).")
    except requests.exceptions.Timeout:
        print("Error: Service is not responding (timeout).")
