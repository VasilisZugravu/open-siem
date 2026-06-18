import re


def op_equals(value, expected):
    return value == expected


def op_contains(value, expected):
    if not isinstance(value, str):
        # Non-string values (int, float, bool, None) cannot contain a substring.
        # Attempting `expected in value` on them would raise TypeError.
        return False
    return expected in value


def op_regex(value, pattern):
    if not isinstance(value, str):
        # re.search requires a string subject; return False rather than raising TypeError.
        return False
    return re.search(pattern, value) is not None


def op_in(value, options):
    return value in options


def match_condition(value, condition):
    """A condition is either a literal (equals) or a dict with one operator key."""
    if isinstance(condition, dict):
        if "contains" in condition:
            return op_contains(value, condition["contains"])
        if "regex" in condition:
            return op_regex(value, condition["regex"])
        if "in" in condition:
            return op_in(value, condition["in"])
        raise ValueError(f"Unknown operator in condition: {condition}")
    return op_equals(value, condition)


def match_conditions(event_dict, conditions):
    """conditions: dict of field_name -> condition. event_dict: dict of field values."""
    for field, condition in conditions.items():
        if not match_condition(event_dict.get(field), condition):
            return False
    return True
