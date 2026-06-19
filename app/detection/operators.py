import re

_regex_cache: dict[str, re.Pattern] = {}  # ponytail: process-global cache, reset on restart (fine for static YAML rules)


def match_condition(value, condition):
    if isinstance(condition, dict):
        if "contains" in condition:
            return isinstance(value, str) and condition["contains"] in value
        if "regex" in condition:
            if not isinstance(value, str):
                return False
            pat = condition["regex"]
            if pat not in _regex_cache:
                _regex_cache[pat] = re.compile(pat)
            return _regex_cache[pat].search(value) is not None
        if "in" in condition:
            return value in condition["in"]
        raise ValueError(f"Unknown operator in condition: {condition}")
    return value == condition


def match_conditions(event_dict, conditions):
    for field, condition in conditions.items():
        if not match_condition(event_dict.get(field), condition):
            return False
    return True
