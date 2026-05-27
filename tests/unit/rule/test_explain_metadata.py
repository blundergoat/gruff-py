"""Unit coverage for the M04 explain-mode metadata: related rules and option_descriptions."""

from dataclasses import FrozenInstanceError

import pytest

from gruffpy.rule.catalog import RELATED_RULES, FalsePositiveShape, documentation_for_rule
from gruffpy.rule.registry import RuleRegistry

_OPTION_DESCRIPTION_RULES = (
    "design.single-implementor-protocol",
    "docs.complex-branch-rationale",
    "docs.dataclass-attributes",
    "docs.missing-class-docstring",
    "docs.useless-docstring",
    "naming.confusing-name",
    "naming.generic-function",
    "naming.module-name-mismatch",
    "naming.short-variable",
    "test-quality.magic-number-assertion",
    "test-quality.mocking-domain-object",
    "test-quality.test-longer-than-sut",
)


@pytest.mark.parametrize("rule_id", _OPTION_DESCRIPTION_RULES)
def test_rule_with_options_has_option_descriptions(rule_id: str) -> None:
    registry = RuleRegistry.defaults()
    definition = registry.get(rule_id).definition()
    docs = documentation_for_rule(rule_id)

    missing = sorted(set(definition.default_options) - set(docs.option_descriptions))
    assert missing == [], f"{rule_id} missing option_descriptions for {missing}"
    extra = sorted(set(docs.option_descriptions) - set(definition.default_options))
    assert extra == [], f"{rule_id} has option_descriptions for unknown options {extra}"


def test_related_rules_only_reference_registered_rule_ids() -> None:
    registry = RuleRegistry.defaults()
    valid_ids = {rule.definition().id for rule in registry.all()}
    invalid = {
        f"{rule_id} -> {sibling}"
        for rule_id, siblings in RELATED_RULES.items()
        for sibling in siblings
        if sibling not in valid_ids
    }
    assert invalid == set()


def test_related_rules_never_list_self() -> None:
    self_refs = [rule_id for rule_id, siblings in RELATED_RULES.items() if rule_id in siblings]
    assert self_refs == []


def test_related_rules_caps_siblings_at_four() -> None:
    over_cap = {
        rule_id: len(siblings) for rule_id, siblings in RELATED_RULES.items() if len(siblings) > 4
    }
    assert over_cap == {}


def test_false_positive_shape_is_a_frozen_dataclass() -> None:
    shape = FalsePositiveShape(shape="x", mitigation="y")
    with pytest.raises(FrozenInstanceError):
        shape.shape = "z"  # type: ignore[misc] -- mutating frozen dataclass is the assertion under test


def test_rule_docs_to_payload_includes_option_descriptions_when_present() -> None:
    docs = documentation_for_rule("docs.dataclass-attributes")

    payload = docs.to_payload()

    assert "optionDescriptions" in payload
    assert payload["optionDescriptions"]["min_fields"].startswith("Minimum dataclass field count")


def test_rule_docs_to_payload_omits_option_descriptions_when_absent() -> None:
    docs = documentation_for_rule("naming.abbreviation")  # not in 12-rule list

    payload = docs.to_payload()

    assert "optionDescriptions" not in payload


def test_rule_docs_to_payload_omits_false_positive_shapes_when_empty() -> None:
    docs = documentation_for_rule("naming.abbreviation")

    payload = docs.to_payload()

    assert "falsePositiveShapes" not in payload
