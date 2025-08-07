import os

from dotenv import load_dotenv

load_dotenv()

PASSWORD_GENERATOR_URL = os.environ.get("PASSWORD_GENERATOR_URL")
PASSWORD_STRENGTH_CHECKER_URL = os.environ.get("PASSWORD_STRENGTH_CHECKER_URL")
REACHED_CHECKER_URL = os.environ.get("BREACHED_CHECKER_URL")
ACTIVITY_LOGGER_URL = os.environ.get("ACTIVITY_LOGGER_URL")
