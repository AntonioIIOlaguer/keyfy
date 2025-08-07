import os

import requests

from keyfy import config


def generate_password(
    pass_type: str = "Strong", length: int | None = None, symbols: bool = False
) -> str:

    params: dict[str, str | int | bool] = {"type": pass_type}

    if length:
        params["length"] = length

    if symbols:
        params["symbols"] = symbols

    try:
        response = requests.get(config.PASSWORD_GENERATOR_URL, params, timeout=5)
        data = response.json()
        generated_password = data.get("password")
        if not generated_password:
            raise ValueError(data.get("detail"))
    except Exception as e:
        raise e

    return generated_password
