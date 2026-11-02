"""Registry-to-config coverage for the checked-in user settings.

The project config mirrors every registered rule so dogfood exercises the
same defaults users receive. These tests ensure option names come only from
registry metadata and that the complete generated-style config loads strictly.
"""

from pathlib import Path
from typing import Any

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.config.yaml_loader import load_gruff_py_yaml
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]

_DEFINITIONS: list[RuleDefinition] = [rule.definition() for rule in RuleRegistry.defaults().all()]


def _repo_yaml_data() -> dict[str, Any]:
    """Load the repository's own ``.gruff-py.yaml``.

    Returns:
        The parsed config mapping.
    """
    return load_gruff_py_yaml(_PROJECT_ROOT / ".gruff-py.yaml")


def _unique(values: Any) -> list[str]:
    """Drop repeated values while keeping first-seen order.

    Args:
        values: Iterable of strings to deduplicate.

    Returns:
        The distinct values in first-seen order.
    """
    return list(dict.fromkeys(values))


def _plain(value: Any) -> Any:
    """Convert nested dicts to dicts with string keys, and lists, tuples, sets and frozensets to lists, for comparison with parsed YAML.

    Args:
        value: Value to convert.

    Returns:
        The converted value; any other value is returned unchanged.
    """
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    return value


def test_repo_yaml_lists_every_pillar_in_catalog_order() -> None:
    """List each registered pillar once, in first-seen registry order, in the repository config's pillar selection."""
    data = _repo_yaml_data()
    assert data["selection"]["pillars"] == _unique(d.pillar.value for d in _DEFINITIONS)


def test_repo_yaml_lists_every_tier_in_catalog_order() -> None:
    """List each registered tier once, in first-seen registry order, in the repository config's tier selection."""
    data = _repo_yaml_data()
    assert data["selection"]["tiers"] == _unique(d.tier.value for d in _DEFINITIONS)


def test_repo_yaml_selection_rules_list_matches_registry_order() -> None:
    """List every registered rule id, in registry order, in the repository config's rule selection."""
    data = _repo_yaml_data()
    assert data["selection"]["rules"] == [d.id for d in _DEFINITIONS]


def test_repo_yaml_rules_section_keys_match_registry_ids() -> None:
    """Give the repository config's rules section exactly one key per registered rule id."""
    data = _repo_yaml_data()
    assert set(data["rules"]) == {d.id for d in _DEFINITIONS}


_SEVERITY_THRESHOLD_DEFINITIONS = [d for d in _DEFINITIONS if d.default_threshold is not None]
_KNOB_THRESHOLD_DEFINITIONS = [d for d in _DEFINITIONS if d.default_threshold is None and d.default_thresholds]


@pytest.mark.parametrize("definition", _DEFINITIONS, ids=lambda d: d.id)
def test_repo_yaml_rule_enabled_matches_definition(definition: RuleDefinition) -> None:
    """Set each rule's enabled flag in the repository config to its definition's default.

    Args:
        definition: Registered rule definition; the cases cover every rule.
    """
    section = _repo_yaml_data()["rules"][definition.id]
    assert section["enabled"] is definition.default_enabled


@pytest.mark.parametrize("definition", _SEVERITY_THRESHOLD_DEFINITIONS, ids=lambda d: d.id)
def test_severity_threshold_rule_uses_single_threshold(definition: RuleDefinition) -> None:
    """Configure each single-threshold rule in the repository config with its default threshold and severity and no thresholds map.

    Args:
        definition: Rule definition with a default threshold; the cases cover each such rule.
    """
    section = _repo_yaml_data()["rules"][definition.id]
    assert "thresholds" not in section
    assert section["threshold"] == definition.default_threshold
    assert section["severity"] == definition.default_severity.value


@pytest.mark.parametrize("definition", _KNOB_THRESHOLD_DEFINITIONS, ids=lambda d: d.id)
def test_knob_rule_keeps_thresholds_block(definition: RuleDefinition) -> None:
    """Configure each named-knob rule in the repository config with its default thresholds map and no single threshold or severity.

    Args:
        definition: Rule definition with named-knob thresholds and no single threshold; the cases cover each such rule.
    """
    section = _repo_yaml_data()["rules"][definition.id]
    assert section.get("thresholds", {}) == _plain(definition.default_thresholds)
    assert "threshold" not in section
    assert "severity" not in section


# Rules whose project-config legitimately overrides the built-in option defaults.
# gruff-py hosts several role-named modules (cli.py, dashboard_server.py,
# python_parser.py, _halstead.py, _secret_scanner_helper.py) whose single
# public class doesn't share enough tokens with the file stem; the project
# extends conventionalModuleNames so the rule recognises them as intentional.
# gruff-py also accepts one predicate name the closed auxiliary-verb list cannot express:
# SourceDiscovery._fallback_applies_at is idiomatic subject-verb English, the calibration class
# backlog.md records for this rule. It is accepted rather than renamed because gruff-spec pins
# "def _fallback_applies_at(" as live M15 review evidence, so a rename to satisfy a style
# advisory would break an immutable evidence anchor.
_RULES_WITH_PROJECT_OPTION_OVERRIDES = frozenset()

_DEFINITIONS_USING_DEFAULT_OPTIONS = [d for d in _DEFINITIONS if d.id not in _RULES_WITH_PROJECT_OPTION_OVERRIDES]


@pytest.mark.parametrize("definition", _DEFINITIONS_USING_DEFAULT_OPTIONS, ids=lambda d: d.id)
def test_repo_yaml_options_match_definition_defaults(definition: RuleDefinition) -> None:
    """Set each rule's options in the repository config to its definition's default options.

    Args:
        definition: Rule definition without project option overrides; the cases cover each, currently every rule.
    """
    section = _repo_yaml_data()["rules"][definition.id]
    assert section.get("options", {}) == _plain(definition.default_options)


@pytest.mark.parametrize("definition", _DEFINITIONS, ids=lambda definition: definition.id)
def test_repo_yaml_option_keys_are_registered_defaults(definition: RuleDefinition) -> None:
    """Keep every configured option inside its rule's sole public allowlist.

    Args:
        definition: Registered rule whose empty or populated option table is checked.
    """
    configured_options = set(_repo_yaml_data()["rules"][definition.id].get("options", {}))
    assert configured_options <= set(definition.default_options)


def test_repo_yaml_loads_without_warnings_under_strict_mode() -> None:
    """Load the complete project config with every warning promoted to failure."""
    defaults = AnalysisConfig.from_registry(RuleRegistry.defaults())
    loader = ConfigLoader(_PROJECT_ROOT, defaults, strict=True)

    loaded, source = loader.load(_PROJECT_ROOT / ".gruff-py.yaml")

    assert source == _PROJECT_ROOT / ".gruff-py.yaml"
    assert loader.warnings == ()
    assert set(loaded.rules) == set(defaults.rules)
