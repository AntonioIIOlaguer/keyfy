from keyfy.core.integrations.breached_checker_service import check_breached_password
from keyfy.core.integrations.strength_checker_service import check_password_strength


def is_int(val):
    """
    Validator for questionary to ensury that a value is an integer.
    """
    try:
        int(val)
        return True
    except ValueError:
        return "Please enter a valid integer."


def is_int_and_within_bounds(val, lower_bound, upper_bound):
    """
    Validator for questionary to ensure that a value is within bounds
    """
    try:
        int_val = int(val)
    except ValueError:
        return "Please enter a valid integer."

    if not (lower_bound <= int_val <= upper_bound):
        return f"Please enter a value between {lower_bound} and {upper_bound}."

    return True


def is_filled(val):
    """
    Validator for questionary if it has a value.
    """
    if val:
        return True
    return "Please enter a key name"


def is_breached(password: str) -> tuple[bool, str]:
    """
    Returns the check_breach_password response as a tuple.
    """
    data = check_breached_password(password)

    return (data["breached"], data["appearances"])


def score_password(password: str) -> tuple[str, list[str]]:
    """Return the strength of the password and feedback"""
    data = check_password_strength(password)
    score = data["score"]
    strength = data["strength"]
    feedback = data["feedback"]

    if score > 4:
        return strength, ["Greate password"]

    return strength, feedback


def display_pass_evaluation(
    breached: bool, appearances: str, strength: str, feedback: list
):
    """
    Displays password evaluation using breached_data, strength and feedback.
    """

    print(f"Password Strength: {strength}")

    if breached:
        print(f"This password was found in {appearances} breaches.")
    else:
        print("This password was never found in any breach.")

    if strength != "strong":
        print("\nSuggestions:")
        for message in feedback:
            print(message)
