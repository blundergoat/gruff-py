"""Keep rule explanations aligned with the options users can configure.

The catalog feeds CLI detail cards and generated rule docs. These tests ensure
every public option has guidance and unrelated empty metadata stays omitted.
"""

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
    "security.unsanitized-markdown-interpolation",
    "test-quality.extends-production-class",
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
    docs = documentation_for_rule("naming.abbreviation")

    payload = docs.to_payload()

    assert "optionDescriptions" not in payload


def test_abbreviation_docs_explain_project_vocabulary_allowlist() -> None:
    """Route idiomatic short forms through the global, replace-not-merge allowlist."""
    docs = documentation_for_rule("naming.abbreviation")

    assert docs.config_keys == ()
    assert "allowlists.acceptedAbbreviations" in docs.fix_guidance
    assert "replaces the universal seed" in docs.fix_guidance
    assert all(token in docs.good_example for token in ("ctx", "cfg", "req", "idx"))


def test_abbreviation_docs_expose_false_positive_shape() -> None:
    """Explain when documented project vocabulary is an accepted exception."""
    docs = documentation_for_rule("naming.abbreviation")
    payload = docs.to_payload()

    assert len(docs.false_positive_shapes) == 1
    assert "project vocabulary" in docs.false_positive_shapes[0].shape
    assert "allowlists.acceptedAbbreviations" in docs.false_positive_shapes[0].mitigation
    assert "falsePositiveShapes" in payload


def test_markdown_rule_explains_slot_specific_sanitizer_options() -> None:
    """Give users separate label and URL guidance in explain-mode payloads."""
    docs = documentation_for_rule("security.unsanitized-markdown-interpolation")

    assert "labelSanitizers" in docs.option_descriptions
    assert "urlSanitizers" in docs.option_descriptions
    assert any("html.escape" in shape.shape for shape in docs.false_positive_shapes)


def test_boolean_prefix_docs_explain_scalar_annotation_boundary() -> None:
    """Tell users why containers and callables receive no predicate-name finding."""
    docs = documentation_for_rule("naming.boolean-prefix")

    assert "Scalar Boolean" in docs.rationale
    assert "containers" in docs.confidence_rationale
    assert "acceptedBooleanNames" in docs.fix_guidance


def test_identifier_quality_docs_separate_domain_names_from_placeholders() -> None:
    """Tell users why `todo` stays valid while draft-name families still warn."""
    docs = documentation_for_rule("naming.identifier-quality")

    assert "todo" in docs.rationale
    assert "result1" in docs.rationale
    assert "work-queue vocabulary" in docs.good_example
