import pytest
from pydantic import ValidationError

from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules
from app.detection.schema import RuleModel, validate_rules


def test_all_rules_pass_schema_validation():
    """Engineering-rigor check: every rule in rules/ must satisfy the strict schema."""
    rules = load_rules(RULES_DIR)
    validated = validate_rules(rules)
    assert len(validated) == 12


def test_rejects_bad_severity():
    rule = {
        "id": "RULE-001", "title": "T", "description": "d", "severity": "extreme",
        "attack_technique": "T1110", "attack_tactic": "Credential Access",
        "detection": {"event_type": "auth_failure", "conditions": {}},
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_rejects_malformed_attack_technique():
    rule = {
        "id": "RULE-001", "title": "T", "description": "d", "severity": "high",
        "attack_technique": "not-a-technique", "attack_tactic": "Credential Access",
        "detection": {"event_type": "auth_failure", "conditions": {}},
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_rejects_unknown_condition_operator():
    rule = {
        "id": "RULE-001", "title": "T", "description": "d", "severity": "high",
        "attack_technique": "T1110", "attack_tactic": "Credential Access",
        "detection": {"event_type": "auth_failure", "conditions": {"command_line": {"startswith": "foo"}}},
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_rejects_condition_with_two_operators():
    rule = {
        "id": "RULE-001", "title": "T", "description": "d", "severity": "high",
        "attack_technique": "T1110", "attack_tactic": "Credential Access",
        "detection": {"event_type": "auth_failure", "conditions": {"command_line": {"contains": "x", "regex": "y"}}},
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_rejects_aggregation_missing_threshold():
    rule = {
        "id": "RULE-001", "title": "T", "description": "d", "severity": "medium",
        "attack_technique": "T1110", "attack_tactic": "Credential Access",
        "detection": {
            "event_type": "auth_failure",
            "conditions": {},
            "aggregation": {"group_by": "src_ip", "timeframe_seconds": 60},
        },
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_rejects_sequence_with_one_step():
    rule = {
        "id": "RULE-009", "title": "T", "description": "d", "severity": "critical",
        "attack_technique": "T1136.001", "attack_tactic": "Persistence",
        "detection": {
            "sequence": [{"event_type": "auth_success", "conditions": {}}],
            "correlate_by": "host",
            "timeframe_seconds": 600,
        },
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_rejects_id_not_matching_rule_nnn_pattern():
    rule = {
        "id": "RULE-X", "title": "T", "description": "d", "severity": "high",
        "attack_technique": "T1110", "attack_tactic": "Credential Access",
        "detection": {"event_type": "auth_failure", "conditions": {}},
    }
    with pytest.raises(ValidationError):
        RuleModel.model_validate(rule)


def test_accepts_valid_aggregation_rule():
    rule = {
        "id": "RULE-001", "title": "SSH Brute Force", "description": "d", "severity": "medium",
        "attack_technique": "T1110", "attack_tactic": "Credential Access",
        "detection": {
            "event_type": "auth_failure",
            "conditions": {"service": "sshd"},
            "aggregation": {"group_by": "src_ip", "threshold": 5, "timeframe_seconds": 60},
        },
        "tags": ["linux", "authentication"],
    }
    validated = RuleModel.model_validate(rule)
    assert validated.detection.aggregation.threshold == 5


def test_accepts_valid_sequence_rule():
    rule = {
        "id": "RULE-009", "title": "Brute Then Persist", "description": "d", "severity": "critical",
        "attack_technique": "T1136.001", "attack_tactic": "Persistence",
        "detection": {
            "sequence": [
                {"event_type": "auth_success", "conditions": {}},
                {"event_type": "command_execution", "conditions": {"command_line": {"contains": "useradd"}}},
            ],
            "correlate_by": "host",
            "timeframe_seconds": 600,
        },
    }
    validated = RuleModel.model_validate(rule)
    assert len(validated.detection.sequence) == 2
