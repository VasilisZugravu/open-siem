"""Pydantic schema for rule YAML files — stricter than rules_loader's field-presence
check. rules_loader only verifies required top-level keys exist (so it stays cheap to
call on every detection cycle); this module is the engineering-rigor pass: it validates
types, enums, regex formats, and the structural shape of each detection variant
(single-event / aggregation / sequence). Run `python -m app.detection.schema` to
validate the live rules/ directory.
"""
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Discriminator, Field, Tag, model_validator

ConditionScalar = Union[str, int, float, bool]


class OperatorCondition(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    contains: str | None = None
    regex: str | None = None
    in_: list[ConditionScalar] | None = Field(default=None, alias="in")

    @model_validator(mode="after")
    def exactly_one_operator(self):
        present = [v for v in (self.contains, self.regex, self.in_) if v is not None]
        if len(present) != 1:
            raise ValueError("condition dict must have exactly one operator key: contains, regex, or in")
        return self


Condition = Union[ConditionScalar, OperatorCondition]


class SingleDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str
    conditions: dict[str, Condition] = {}


class Aggregation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group_by: str
    threshold: int = Field(gt=0)
    timeframe_seconds: int = Field(gt=0)


class AggregationDetection(SingleDetection):
    aggregation: Aggregation


class SequenceStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_type: str
    conditions: dict[str, Condition] = {}


class SequenceDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sequence: list[SequenceStep] = Field(min_length=2, max_length=2)
    correlate_by: str
    timeframe_seconds: int = Field(gt=0)


def _detection_kind(v):
    """Discriminate which detection variant a raw dict (or already-built model) is."""
    if isinstance(v, dict):
        if "sequence" in v:
            return "sequence"
        if "aggregation" in v:
            return "aggregation"
        return "single"
    if isinstance(v, SequenceDetection):
        return "sequence"
    if isinstance(v, AggregationDetection):
        return "aggregation"
    return "single"


Detection = Annotated[
    Union[
        Annotated[SequenceDetection, Tag("sequence")],
        Annotated[AggregationDetection, Tag("aggregation")],
        Annotated[SingleDetection, Tag("single")],
    ],
    Discriminator(_detection_kind),
]


class RuleModel(BaseModel):
    """Schema for a single rule YAML file."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^RULE-\d{3}$")
    title: str
    description: str
    severity: Literal["low", "medium", "high", "critical"]
    attack_technique: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    attack_tactic: str
    detection: Detection
    tags: list[str] = []


def validate_rules(rules):
    """Validate a list of already-loaded rule dicts. Returns the list of RuleModel
    instances. Raises pydantic.ValidationError on the first invalid rule, annotated
    with the rule's id."""
    validated = []
    for rule in rules:
        try:
            validated.append(RuleModel.model_validate(rule))
        except Exception as e:
            raise ValueError(f"Rule {rule.get('id', '<unknown>')} failed schema validation: {e}") from e
    return validated


if __name__ == "__main__":
    from app.detection import RULES_DIR
    from app.detection.rules_loader import load_rules

    rules = load_rules(RULES_DIR)
    validate_rules(rules)
    print(f"All {len(rules)} rules in {RULES_DIR} passed schema validation.")
