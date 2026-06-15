from app.detection import RULES_DIR
from app.detection.rules_loader import load_rules


def test_all_eight_rules_load():
    rules = load_rules(RULES_DIR)
    rule_ids = {r["id"] for r in rules}
    assert rule_ids == {
        "RULE-001", "RULE-002", "RULE-003", "RULE-004",
        "RULE-005", "RULE-006", "RULE-007", "RULE-008",
    }


def test_rule_attack_techniques_are_unique():
    rules = load_rules(RULES_DIR)
    techniques = [r["attack_technique"] for r in rules]
    assert len(techniques) == len(set(techniques))
