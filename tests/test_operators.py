from app.detection.operators import match_condition, match_conditions


def test_equals_match():
    assert match_condition("powershell.exe", "powershell.exe") is True
    assert match_condition("cmd.exe", "powershell.exe") is False


def test_contains_match():
    assert match_condition("powershell.exe -enc abc", {"contains": "-enc"}) is True
    assert match_condition("powershell.exe -nop", {"contains": "-enc"}) is False
    assert match_condition(None, {"contains": "-enc"}) is False


def test_regex_match():
    assert match_condition("/usr/sbin/visudo", {"regex": "(shadow|visudo)"}) is True
    assert match_condition("/bin/ls", {"regex": "(shadow|visudo)"}) is False


def test_in_match():
    assert match_condition("cmd.exe", {"in": ["cmd.exe", "powershell.exe"]}) is True
    assert match_condition("bash", {"in": ["cmd.exe", "powershell.exe"]}) is False


def test_match_conditions_all_must_match():
    event = {"process_name": "powershell.exe", "command_line": "powershell.exe -enc abc"}
    conditions = {"process_name": "powershell.exe", "command_line": {"contains": "-enc"}}
    assert match_conditions(event, conditions) is True


def test_match_conditions_fails_if_one_condition_fails():
    event = {"process_name": "powershell.exe", "command_line": "powershell.exe -nop"}
    conditions = {"process_name": "powershell.exe", "command_line": {"contains": "-enc"}}
    assert match_conditions(event, conditions) is False


def test_match_conditions_missing_field_is_no_match():
    event = {"process_name": "powershell.exe"}
    conditions = {"command_line": {"contains": "-enc"}}
    assert match_conditions(event, conditions) is False


# ── H2: type-safety regression tests ─────────────────────────────────────────

def test_contains_numeric_value_no_exception():
    """op_contains must not raise TypeError on a numeric field value (e.g. dest_port: 4444).
    Numeric values cannot contain a substring, so the result must be False."""
    assert match_condition(4444, {"contains": "444"}) is False


def test_regex_numeric_value_no_exception():
    """op_regex must not raise TypeError on a numeric field value.
    Numeric values cannot be regex-searched, so the result must be False."""
    assert match_condition(4444, {"regex": r"\d+"}) is False


def test_contains_bool_value_no_exception():
    """op_contains must handle bool (a subtype of int) without raising TypeError."""
    assert match_condition(True, {"contains": "True"}) is False


def test_regex_bool_value_no_exception():
    """op_regex must handle bool without raising TypeError."""
    assert match_condition(False, {"regex": "False"}) is False
