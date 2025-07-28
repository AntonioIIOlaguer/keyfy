import sys

from keyfy.core.interactive_mode import landing_page
from keyfy.core.script_mode import cli


def main():
    if len(sys.argv) > 1:
        cli()
    else:
        landing_page()


if __name__ == "__main__":
    main()
