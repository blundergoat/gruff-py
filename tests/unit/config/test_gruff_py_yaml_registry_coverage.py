from pathlib import Path
from typing import Any

import pytest

from gruffpy.config.yaml_loader import load_gruff_py_yaml
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_DEFINITIONS: list[RuleDefinition] = [rule.definition() for rule in RuleRegistry.defaults().all()]


def _repo_yaml_data() -> dict[str, Any]:
    return load_gruff_py_yaml(_PROJECT_ROOT / ".gruff-py.yaml")


def _unique(values: Any) -> list[str]:
    return list(dict.fromkeys(values))


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    return value


def test_repo_yaml_lists_every_pillar_in_catalog_order() -> None:
    data = _repo_yaml_data()
    assert data["selection"]["pillars"] == _unique(d.pillar.value for d in _DEFINITIONS)


def test_repo_yaml_lists_every_tier_in_catalog_order() -> None:
    data = _repo_yaml_data()
    assert data["selection"]["tiers"] == _unique(d.tier.value for d in _DEFINITIONS)


def test_repo_yaml_selection_rules_list_matches_registry_order() -> None:
    data = _repo_yaml_data()
    assert data["selection"]["rules"] == [d.id for d in _DEFINITIONS]


def test_repo_yaml_rules_section_keys_match_registry_ids() -> None:
    data = _repo_yaml_data()
    assert set(data["rules"]) == {d.id for d in _DEFINITIONS}


_WARNING_ERROR_DEFINITIONS = [
    d for d in _DEFINITIONS if set(d.default_thresholds) == {"warning", "error"}
]
_OTHER_THRESHOLD_DEFINITIONS = [
    d for d in _DEFINITIONS if set(d.default_thresholds) != {"warning", "error"}
]


@pytest.mark.parametrize("definition", _DEFINITIONS, ids=lambda d: d.id)
def test_repo_yaml_rule_enabled_matches_definition(definition: RuleDefinition) -> None:
    section = _repo_yaml_data()["rules"][definition.id]
    assert section["enabled"] is definition.default_enabled


@pytest.mark.parametrize("definition", _WARNING_ERROR_DEFINITIONS, ids=lambda d: d.id)
def test_warning_error_rule_collapses_to_single_threshold(definition: RuleDefinition) -> None:
    section = _repo_yaml_data()["rules"][definition.id]
    assert "thresholds" not in section
    assert section["threshold"] == definition.default_thresholds["error"]
    assert section["severity"] == "error"


@pytest.mark.parametrize("definition", _OTHER_THRESHOLD_DEFINITIONS, ids=lambda d: d.id)
def test_non_warning_error_rule_keeps_full_thresholds_block(
    definition: RuleDefinition,
) -> None:
    section = _repo_yaml_data()["rules"][definition.id]
    assert section.get("thresholds", {}) == _plain(definition.default_thresholds)
    assert "threshold" not in section
    assert "severity" not in section


# Rules whose project-config legitimately overrides the built-in option defaults.
# gruff-py hosts several role-named modules (cli.py, dashboard_server.py,
# python_parser.py, _halstead.py, _secret_scanner_helper.py) whose single
# public class doesn't share enough tokens with the file stem; the project
# extends conventionalModuleNames so the rule recognises them as intentional.
_RULES_WITH_PROJECT_OPTION_OVERRIDES = frozenset({"naming.module-name-mismatch"})

_DEFINITIONS_USING_DEFAULT_OPTIONS = [
    d for d in _DEFINITIONS if d.id not in _RULES_WITH_PROJECT_OPTION_OVERRIDES
]


@pytest.mark.parametrize("definition", _DEFINITIONS_USING_DEFAULT_OPTIONS, ids=lambda d: d.id)
def test_repo_yaml_options_match_definition_defaults(definition: RuleDefinition) -> None:
    section = _repo_yaml_data()["rules"][definition.id]
    assert section.get("options", {}) == _plain(definition.default_options)


def test_module_name_mismatch_extends_conventional_module_names() -> None:
    """The project-config override is the documented mechanism; assert its
    shape so accidental edits don't silently break the rule's exemptions."""
    section = _repo_yaml_data()["rules"]["naming.module-name-mismatch"]
    configured_names = section["options"]["conventionalModuleNames"]
    # Defaults must stay present (don't drop the built-in exemptions).
    builtin_defaults = {"constants", "exceptions", "helpers", "protocols", "types"}
    assert builtin_defaults.issubset(configured_names)
    # Project-specific role-named modules must be exempted.
    project_overrides = {
        "cli",
        "dashboard_server",
        "python_parser",
        "_halstead",
        "_secret_scanner_helper",
        "_comment_scanner",
    }
    assert project_overrides.issubset(configured_names)
