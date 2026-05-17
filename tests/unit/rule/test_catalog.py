import importlib
import inspect
import pkgutil
from pathlib import Path
from typing import Any

import gruffpy.rule
from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.finding.pillar import Pillar
from gruffpy.rule.catalog import (
    BUILTIN_RULES,
    RuleDocs,
    catalog_definitions,
    documentation_for_rule,
)
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


def test_rule_ids_match_pillar_prefix_convention() -> None:
    for definition in catalog_definitions():
        prefixes = _PREFIXES_BY_PILLAR[definition.pillar]
        assert definition.id.startswith(prefixes), definition.id


def test_no_concrete_rule_class_is_omitted_from_catalog() -> None:
    catalog_classes = {type(entry.create()) for entry in BUILTIN_RULES}
    concrete_classes = set(_concrete_rule_classes())

    assert concrete_classes == catalog_classes


def test_every_builtin_rule_has_required_docs_metadata() -> None:
    for definition in catalog_definitions():
        docs = documentation_for_rule(definition.id)
        assert isinstance(docs, RuleDocs)
        assert docs.rationale
        assert docs.fix_guidance
        assert docs.bad_example
        assert docs.good_example
        assert docs.confidence_rationale
        assert docs.to_payload()["rationale"] == docs.rationale


def test_metric_rules_publish_formula_provenance() -> None:
    for definition in catalog_definitions():
        docs = documentation_for_rule(definition.id)
        if definition.id in _FORMULA_RULES:
            assert docs.formula_provenance
        else:
            assert docs.formula_provenance == ""


def test_size_and_complexity_threshold_docs_publish_standard_metadata_contract() -> None:
    for definition in catalog_definitions():
        docs = documentation_for_rule(definition.id)
        if definition.pillar in {Pillar.SIZE, Pillar.COMPLEXITY, Pillar.MAINTAINABILITY}:
            assert docs.threshold_metadata_keys == (
                "measuredValue",
                "threshold",
                "thresholdDirection",
                "thresholdType",
            )
            assert docs.threshold_direction in {"above", "below"}


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
