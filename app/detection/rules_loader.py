import os
import yaml

REQUIRED_FIELDS = ["id", "title", "severity", "attack_technique", "attack_tactic", "detection"]


def load_rule_file(path):
    with open(path) as f:
        rule = yaml.safe_load(f)

    for field in REQUIRED_FIELDS:
        if field not in rule:
            raise ValueError(f"Rule {path} missing required field: {field}")

    if "sequence" not in rule["detection"] and "event_type" not in rule["detection"]:
        raise ValueError(f"Rule {path} detection block missing event_type or sequence")

    return rule


def load_rules(rules_dir):
    rules = []
    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith((".yml", ".yaml")):
            rules.append(load_rule_file(os.path.join(rules_dir, filename)))
    return rules
