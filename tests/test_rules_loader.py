import yaml
from app.detection.rules_loader import load_rule_file, load_rules


def test_load_rule_file_valid(tmp_path):
    rule_data = {
        "id": "RULE-TEST",
        "title": "Test Rule",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"event_type": "test_event", "conditions": {"foo": "bar"}},
    }
    rule_file = tmp_path / "test_rule.yml"
    rule_file.write_text(yaml.dump(rule_data))

    rule = load_rule_file(str(rule_file))
    assert rule["id"] == "RULE-TEST"
    assert rule["detection"]["event_type"] == "test_event"


def test_load_rule_file_missing_field(tmp_path):
    rule_data = {"id": "RULE-TEST", "title": "Test Rule"}
    rule_file = tmp_path / "bad_rule.yml"
    rule_file.write_text(yaml.dump(rule_data))

    try:
        load_rule_file(str(rule_file))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "severity" in str(e)


def test_load_rule_file_missing_event_type(tmp_path):
    rule_data = {
        "id": "RULE-TEST",
        "title": "Test Rule",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"conditions": {"foo": "bar"}},
    }
    rule_file = tmp_path / "bad_rule.yml"
    rule_file.write_text(yaml.dump(rule_data))

    try:
        load_rule_file(str(rule_file))
        assert False, "expected ValueError"
    except ValueError as e:
        assert "event_type" in str(e)


def test_load_rules_from_directory(tmp_path):
    rule_data = {
        "id": "RULE-A",
        "title": "Rule A",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"event_type": "test_event"},
    }
    (tmp_path / "rule_a.yml").write_text(yaml.dump(rule_data))
    (tmp_path / "notes.txt").write_text("not a rule")

    rules = load_rules(str(tmp_path))
    assert len(rules) == 1
    assert rules[0]["id"] == "RULE-A"
