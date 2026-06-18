import yaml
import pytest
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
        "id": "RULE-001",           # must match RULE-\d{3} for Pydantic
        "title": "Rule A",
        "description": "Test rule for directory loading.",
        "severity": "low",
        "attack_technique": "T1000",
        "attack_tactic": "Testing",
        "detection": {"event_type": "test_event"},
        "tags": [],
    }
    (tmp_path / "rule_a.yml").write_text(yaml.dump(rule_data))
    (tmp_path / "notes.txt").write_text("not a rule")

    rules = load_rules(str(tmp_path))
    assert len(rules) == 1
    assert rules[0]["id"] == "RULE-001"


def test_sequence_rule_loads_without_error(tmp_path):
    import yaml
    rule = {
        "id": "RULE-SEQ",
        "title": "Seq Rule",
        "severity": "high",
        "attack_technique": "T9999",
        "attack_tactic": "Testing",
        "detection": {
            "sequence": [
                {"event_type": "a", "conditions": {}},
                {"event_type": "b", "conditions": {}},
            ],
            "correlate_by": "host",
            "timeframe_seconds": 60,
        },
    }
    p = tmp_path / "seq_rule.yml"
    p.write_text(yaml.dump(rule))
    from app.detection.rules_loader import load_rule_file
    result = load_rule_file(str(p))
    assert result["id"] == "RULE-SEQ"


def test_rule_missing_both_event_type_and_sequence_raises(tmp_path):
    rule = {
        "id": "RULE-BAD",
        "title": "Bad",
        "severity": "low",
        "attack_technique": "T0000",
        "attack_tactic": "Testing",
        "detection": {"conditions": {}},
    }
    p = tmp_path / "bad_rule.yml"
    p.write_text(yaml.dump(rule))
    with pytest.raises(ValueError, match="event_type or sequence"):
        load_rule_file(str(p))


# ── M2: Pydantic validation at load ──────────────────────────────────────────

def _valid_rule_data(rule_id="RULE-001"):
    """Return a fully valid rule dict (passes both cheap check and Pydantic)."""
    return {
        "id": rule_id,
        "title": "Valid Rule",
        "description": "A rule used in tests.",
        "severity": "high",
        "attack_technique": "T1059.001",
        "attack_tactic": "Execution",
        "detection": {"event_type": "process_creation", "conditions": {}},
        "tags": [],
    }


def test_load_rules_skips_pydantic_invalid_rule(tmp_path):
    """M2: A rule that passes the cheap presence-check but fails Pydantic
    schema validation (bad severity enum) must be silently skipped; a valid
    sibling rule must still be returned."""
    (tmp_path / "valid.yml").write_text(yaml.dump(_valid_rule_data("RULE-001")))

    invalid = _valid_rule_data("RULE-002")
    invalid["severity"] = "SUPER_CRITICAL"  # not in Literal["low","medium","high","critical"]
    (tmp_path / "invalid.yml").write_text(yaml.dump(invalid))

    rules = load_rules(str(tmp_path))

    assert len(rules) == 1
    assert rules[0]["id"] == "RULE-001"


def test_load_rules_skips_rule_with_bad_id_format(tmp_path):
    """M2: A rule whose id doesn't match the RULE-NNN pattern is rejected."""
    bad_id = _valid_rule_data()
    bad_id["id"] = "BADFORMAT"
    (tmp_path / "bad_id.yml").write_text(yaml.dump(bad_id))

    rules = load_rules(str(tmp_path))
    assert rules == []


def test_load_rules_caches_unchanged_directory(tmp_path):
    """M2: Repeated calls without file-system changes must return the same
    list object (mtime-based cache hit)."""
    (tmp_path / "rule.yml").write_text(yaml.dump(_valid_rule_data()))

    result1 = load_rules(str(tmp_path))
    result2 = load_rules(str(tmp_path))

    assert result1 is result2
