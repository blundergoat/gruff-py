import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any

import pytest

import gruffpy.rule
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.finding.pillar import Pillar
from gruffpy.rule.catalog import (
    BUILTIN_RULES,
    RuleDocs,
    catalog_definitions,
    documentation_for_rule,
)
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.project_rule import ProjectRuleProtocol
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.rule import Rule

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_PREFIXES_BY_PILLAR = {
    Pillar.SIZE: ("size.",),
    Pillar.COMPLEXITY: ("complexity.",),
    Pillar.MAINTAINABILITY: ("complexity.", "maintainability."),
    Pillar.DEAD_CODE: ("dead-code.", "waste."),
    Pillar.NAMING: ("naming.",),
    Pillar.DOCUMENTATION: ("docs.",),
    Pillar.SECURITY: ("security.",),
    Pillar.SENSITIVE_DATA: ("sensitive-data.",),
    Pillar.TEST_QUALITY: ("test-quality.",),
    Pillar.DESIGN: ("design.",),
}

_FORMULA_RULES = {
    "complexity.cyclomatic",
    "complexity.halstead-volume",
    "complexity.maintainability-index",
    "complexity.npath",
}

_ALL_DEFINITIONS = catalog_definitions()


def test_catalog_entries_are_importable_and_unique() -> None:
    definitions = catalog_definitions()
    ids = [definition.id for definition in definitions]

    assert len(definitions) == len(BUILTIN_RULES)
    assert len(ids) == len(set(ids))
    assert ids == [entry.create().definition().id for entry in BUILTIN_RULES]


def test_registry_defaults_consumes_catalog_entries() -> None:
    catalog_ids = {definition.id for definition in catalog_definitions()}
    registry_ids = {rule.definition().id for rule in RuleRegistry.defaults().all()}

    assert registry_ids == catalog_ids
    assert AnalysisConfig.from_registry(RuleRegistry.defaults()).rules.keys() == registry_ids


@pytest.mark.parametrize("definition", _ALL_DEFINITIONS, ids=lambda d: d.id)
def test_rule_id_matches_pillar_prefix_convention(definition: RuleDefinition) -> None:
    prefixes = _PREFIXES_BY_PILLAR[definition.pillar]
    assert definition.id.startswith(prefixes)


def test_no_concrete_rule_class_is_omitted_from_catalog() -> None:
    catalog_classes = {type(entry.create()) for entry in BUILTIN_RULES}
    concrete_classes = set(_concrete_rule_classes())

    assert concrete_classes == catalog_classes


def test_documentation_for_rule_returns_rule_docs_with_payload_round_trip() -> None:
    sample_id = _ALL_DEFINITIONS[0].id
    docs = documentation_for_rule(sample_id)
    assert isinstance(docs, RuleDocs)
    assert docs.to_payload()["rationale"] == docs.rationale


@pytest.mark.parametrize("definition", _ALL_DEFINITIONS, ids=lambda d: d.id)
def test_builtin_rule_has_required_docs_metadata(definition: RuleDefinition) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.rationale
    assert docs.fix_guidance
    assert docs.bad_example
    assert docs.good_example
    assert docs.confidence_rationale


_METRIC_DEFINITIONS = [d for d in _ALL_DEFINITIONS if d.id in _FORMULA_RULES]
_NON_METRIC_DEFINITIONS = [d for d in _ALL_DEFINITIONS if d.id not in _FORMULA_RULES]


@pytest.mark.parametrize("definition", _METRIC_DEFINITIONS, ids=lambda d: d.id)
def test_metric_rule_publishes_formula_provenance(definition: RuleDefinition) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.formula_provenance


@pytest.mark.parametrize("definition", _NON_METRIC_DEFINITIONS, ids=lambda d: d.id)
def test_non_metric_rule_has_no_formula_provenance(definition: RuleDefinition) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.formula_provenance == ""


_SIZE_OR_COMPLEXITY_PILLARS = {Pillar.SIZE, Pillar.COMPLEXITY, Pillar.MAINTAINABILITY}
_SIZE_AND_COMPLEXITY_DEFINITIONS = [
    d for d in _ALL_DEFINITIONS if d.pillar in _SIZE_OR_COMPLEXITY_PILLARS
]


@pytest.mark.parametrize("definition", _SIZE_AND_COMPLEXITY_DEFINITIONS, ids=lambda d: d.id)
def test_size_and_complexity_threshold_docs_publish_standard_metadata_contract(
    definition: RuleDefinition,
) -> None:
    docs = documentation_for_rule(definition.id)
    assert docs.threshold_metadata_keys == (
        "measuredValue",
        "threshold",
        "thresholdDirection",
        "thresholdType",
    )
    assert docs.threshold_direction in {"above", "below"}


def test_selected_security_rules_publish_taxonomy_metadata() -> None:
    docs = documentation_for_rule("security.sql-concatenation")
    assert docs.security_metadata["cwe"] == ["CWE-89"]
    assert docs.to_payload()["security"]["securitySeverity"] == "high"

    yaml_docs = documentation_for_rule("security.unsafe-yaml-load")
    assert yaml_docs.security_metadata["cwe"] == ["CWE-502"]


def _concrete_rule_classes() -> list[type[Any]]:
    classes: list[type[Any]] = []
    for module_info in pkgutil.walk_packages(gruffpy.rule.__path__, gruffpy.rule.__name__ + "."):
        if not module_info.name.endswith("_rule"):
            continue
        module = importlib.import_module(module_info.name)
        for _name, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__:
                continue
            if inspect.isabstract(cls):
                continue
            if _is_rule_class(cls):
                classes.append(cls)
    return sorted(classes, key=lambda cls: f"{cls.__module__}.{cls.__name__}")


def _is_rule_class(cls: type[Any]) -> bool:
    if issubclass(cls, Rule):
        return cls is not Rule
    try:
        instance = cls()
    except TypeError:
        return False
    return isinstance(instance, ProjectRuleProtocol)
