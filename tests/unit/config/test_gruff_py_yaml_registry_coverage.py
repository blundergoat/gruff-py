from pathlib import Path
from typing import Any

import pytest

from gruffpy.config.yaml_loader import load_gruff_py_yaml
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_REPO_YAML_DATA: dict[str, Any] = load_gruff_py_yaml(_PROJECT_ROOT / ".gruff-py.yaml")
_DEFINITIONS: list[RuleDefinition] = [rule.definition() for rule in RuleRegistry.defaults().all()]


def _unique(values: Any) -> list[str]:
    return list(dict.fromkeys(values))


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    return value


def test_repo_yaml_lists_every_pillar_in_catalog_order() -> None:
    assert _REPO_YAML_DATA["selection"]["pillars"] == _unique(d.pillar.value for d in _DEFINITIONS)


def test_repo_yaml_lists_every_tier_in_catalog_order() -> None:
    assert _REPO_YAML_DATA["selection"]["tiers"] == _unique(d.tier.value for d in _DEFINITIONS)


def test_repo_yaml_selection_rules_list_matches_registry_order() -> None:
    assert _REPO_YAML_DATA["selection"]["rules"] == [d.id for d in _DEFINITIONS]


def test_repo_yaml_rules_section_keys_match_registry_ids() -> None:
    assert set(_REPO_YAML_DATA["rules"]) == {d.id for d in _DEFINITIONS}


_WARNING_ERROR_DEFINITIONS = [
    d for d in _DEFINITIONS if set(d.default_thresholds) == {"warning", "error"}
]
_OTHER_THRESHOLD_DEFINITIONS = [
    d for d in _DEFINITIONS if set(d.default_thresholds) != {"warning", "error"}
]


@pytest.mark.parametrize("definition", _DEFINITIONS, ids=lambda d: d.id)
def test_repo_yaml_rule_enabled_matches_definition(definition: RuleDefinition) -> None:
    section = _REPO_YAML_DATA["rules"][definition.id]
    assert section["enabled"] is definition.default_enabled


@pytest.mark.parametrize("definition", _WARNING_ERROR_DEFINITIONS, ids=lambda d: d.id)
def test_warning_error_rule_collapses_to_single_threshold(definition: RuleDefinition) -> None:
    section = _REPO_YAML_DATA["rules"][definition.id]
    assert "thresholds" not in section
    assert section["threshold"] == definition.default_thresholds["error"]
    assert section["severity"] == "error"


@pytest.mark.parametrize("definition", _OTHER_THRESHOLD_DEFINITIONS, ids=lambda d: d.id)
def test_non_warning_error_rule_keeps_full_thresholds_block(
    definition: RuleDefinition,
) -> None:
    section = _REPO_YAML_DATA["rules"][definition.id]
    assert section.get("thresholds", {}) == _plain(definition.default_thresholds)
    assert "threshold" not in section
    assert "severity" not in section


@pytest.mark.parametrize("definition", _DEFINITIONS, ids=lambda d: d.id)
def test_repo_yaml_options_match_definition_defaults(definition: RuleDefinition) -> None:
    section = _REPO_YAML_DATA["rules"][definition.id]
    assert section.get("options", {}) == _plain(definition.default_options)
