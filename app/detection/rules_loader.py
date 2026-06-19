import logging
import os
import yaml

logger = logging.getLogger(__name__)

RULES_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "..", "rules")
)

# These are the fields checked by load_rule_file's cheap presence-guard before
# Pydantic validation. `description` is also required by the Pydantic schema but
# is not listed here — load_rules calls validate_rules() after this check, so a
# rule missing `description` will be caught and skipped at the Pydantic stage.
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
    with open(path, encoding="utf-8") as f:
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
        # C1: Return a shallow copy so callers cannot mutate the cached list and
        # corrupt subsequent detection cycles.
        return list(cached["rules"])

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

    # C1: store an independent copy so a caller who mutates the returned list
    # cannot corrupt the cached copy for subsequent cycles.
    _cache[rules_dir] = {"mtimes": current_mtimes, "rules": list(rules)}
    return rules
