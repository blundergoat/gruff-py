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
    "docs.dataclass-attributes",
    "docs.missing-class-docstring",
    "naming.generic-function",
    "naming.short-variable",
    "test-quality.mocking-domain-object",
    "test-quality.test-longer-than-sut",
)


@pytest.mark.parametrize("rule_id", _OPTION_DESCRIPTION_RULES)
def test_rule_with_options_has_option_descriptions(rule_id: str) -> None:
    """Describe exactly the default options of each listed rule, with no option description missing or extra.

    Args:
        rule_id: Rule from the module's option-description list; the cases cover each listed rule.

    Returns:
        None. Fails if a default option key lacks a description entry or a description names an unknown option.
    """
    registry = RuleRegistry.defaults()
    definition = registry.get(rule_id).definition()
    docs = documentation_for_rule(rule_id)

    missing = sorted(set(definition.default_options) - set(docs.option_descriptions))
    assert missing == [], f"{rule_id} missing option_descriptions for {missing}"
    extra = sorted(set(docs.option_descriptions) - set(definition.default_options))
    assert extra == [], f"{rule_id} has option_descriptions for unknown options {extra}"


def test_related_rules_only_reference_registered_rule_ids() -> None:
    """Name only registered rule ids among each rule's related rules.

    Returns:
        None. Fails if a listed related rule id is absent from the default registry.
    """
    registry = RuleRegistry.defaults()
    valid_ids = {rule.definition().id for rule in registry.all()}
    invalid = {f"{rule_id} -> {sibling}" for rule_id, siblings in RELATED_RULES.items() for sibling in siblings if sibling not in valid_ids}
    assert invalid == set()


def test_related_rules_never_list_self() -> None:
    """Never list a rule among its own related rules.

    Returns:
        None. Fails if a rule id appears in its own related-rule list.
    """
    self_refs = [rule_id for rule_id, siblings in RELATED_RULES.items() if rule_id in siblings]
    assert self_refs == []


def test_related_rules_caps_siblings_at_four() -> None:
    """List at most four related rules for each rule.

    Returns:
        None. Fails if any rule lists more than four related rules.
    """
    over_cap = {rule_id: len(siblings) for rule_id, siblings in RELATED_RULES.items() if len(siblings) > 4}
    assert over_cap == {}


def test_false_positive_shape_is_a_frozen_dataclass() -> None:
    """Check that a false-positive shape rejects assignment to its shape field.

    Returns:
        None. Requires FrozenInstanceError from the attempted assignment.
    """
    shape = FalsePositiveShape(shape="x", mitigation="y")
    with pytest.raises(FrozenInstanceError):
        shape.shape = "z"  # type: ignore[misc] -- mutating frozen dataclass is the assertion under test


def test_rule_docs_to_payload_includes_option_descriptions_when_present() -> None:
    """Include option descriptions in a rule's documentation payload when the rule has them.

    Returns:
        None. Checks that the payload includes optionDescriptions and the expected min_fields description prefix.
    """
    docs = documentation_for_rule("docs.dataclass-attributes")

    payload = docs.to_payload()

    assert "optionDescriptions" in payload
    assert payload["optionDescriptions"]["min_fields"].startswith("Minimum dataclass field count")


def test_rule_docs_to_payload_omits_option_descriptions_when_absent() -> None:
    """Omit the option-descriptions key from a rule's documentation payload when the rule has none.

    Returns:
        None. Fails if the abbreviation rule payload includes optionDescriptions.
    """
    docs = documentation_for_rule("naming.abbreviation")

    payload = docs.to_payload()

    assert "optionDescriptions" not in payload


def test_abbreviation_docs_explain_project_vocabulary_allowlist() -> None:
    """Check that the abbreviation guidance describes the global allowlist as a replacement for the universal seed.

    Returns:
        None. Checks the empty per-rule config keys, the global allowlist guidance, and the example short forms.
    """
    docs = documentation_for_rule("naming.abbreviation")

    assert docs.config_keys == ()
    assert "allowlists.acceptedAbbreviations" in docs.fix_guidance
    assert "replaces the universal seed" in docs.fix_guidance
    assert all(token in docs.good_example for token in ("ctx", "cfg", "req", "idx"))


def test_abbreviation_docs_expose_false_positive_shape() -> None:
    """Explain when documented project vocabulary is an accepted exception.

    Returns:
        None. Checks the single project-vocabulary exception, its allowlist mitigation, and the falsePositiveShapes payload key.
    """
    docs = documentation_for_rule("naming.abbreviation")
    payload = docs.to_payload()

    assert len(docs.false_positive_shapes) == 1
    assert "project vocabulary" in docs.false_positive_shapes[0].shape
    assert "allowlists.acceptedAbbreviations" in docs.false_positive_shapes[0].mitigation
    assert "falsePositiveShapes" in payload


def test_identifier_quality_docs_separate_domain_names_from_placeholders() -> None:
    """Keep identifier-quality guidance anchored to todo, result1 and work-queue vocabulary.

    Returns:
        None. Checks the rationale for both placeholder names and the good example for work-queue vocabulary.
    """
    docs = documentation_for_rule("naming.identifier-quality")

    assert "todo" in docs.rationale
    assert "result1" in docs.rationale
    assert "work-queue vocabulary" in docs.good_example
