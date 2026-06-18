import logging
import os
import yaml

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = ["id", "title", "severity", "attack_technique", "attack_tactic", "detection"]

# M2: Mtime-based cache so the scheduler's 30s loop doesn't re-parse and
# re-validate rule YAML on every tick. Keyed by rules_dir; invalidated when
# any YAML file's mtime changes or the directory listing changes.
_cache: dict = {}


def _dir_mtimes(rules_dir):
    """Return a dict mapping YAML filename → mtime for every rule file."""
    mtimes = {}
    for filename in sorted(os.listdir(rules_dir)):
        if filename.endswith((".yml", ".yaml")):
            mtimes[filename] = os.path.getmtime(os.path.join(rules_dir, filename))
    return mtimes


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
    # M2: Return cached result if the directory contents haven't changed.
    current_mtimes = _dir_mtimes(rules_dir)
    cached = _cache.get(rules_dir)
    if cached is not None and cached["mtimes"] == current_mtimes:
        return cached["rules"]

    # M2: Import here to avoid a circular import at module load time.
    from app.detection.schema import validate_rules as _pydantic_validate

    rules = []
    for filename in sorted(current_mtimes):
        path = os.path.join(rules_dir, filename)
        try:
            rule = load_rule_file(path)
            # M2: Full Pydantic validation (types, enums, regex formats, structure).
            # Skip + warn on bad files rather than crashing the detection loop.
            _pydantic_validate([rule])
            rules.append(rule)
        except Exception as exc:
            logger.warning("Skipping invalid rule file %s: %s", path, exc)

    _cache[rules_dir] = {"mtimes": current_mtimes, "rules": rules}
    return rules
