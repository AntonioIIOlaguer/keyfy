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
