import sys

from src.interactive_mode import landing_page
from src.script_mode import cli

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        landing_page()
