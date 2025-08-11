import requests

from keyfy import config
from keyfy.core.integrations.service_error import PortMissingError


def generate_password(
    pass_type: str = "Strong", length: int | None = None, symbols: bool = False
) -> str:

    params: dict[str, str | int | bool] = {"type": pass_type}

    if length:
        params["length"] = length

    if symbols:
        params["symbols"] = symbols

    try:
        if config.PASSWORD_STRENGTH_CHECKER_URL is None:
            raise PortMissingError(
                "Error: Port is missing for the password generator service."
            )

        response = requests.get(config.PASSWORD_GENERATOR_URL, params, timeout=5)
        response.raise_for_status()

        data = response.json()
        generated_password = data.get("password")
        if not generated_password:
            raise ValueError("detail", "Password not found in service response.")

        return generated_password

    except PortMissingError:
        raise
    except requests.exceptions.ConnectionError:
        raise requests.exceptions.ConnectionError(
            "Error: Service is not available (connection failed)."
        )
    except requests.exceptions.Timeout:
        raise requests.exceptions.Timeout("Error: Service is not responding (timeout).")
    except Exception as e:
        raise e
