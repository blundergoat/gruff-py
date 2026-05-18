from pathlib import Path
from typing import Any

from gruffpy.config.yaml_loader import load_gruff_py_yaml
from gruffpy.rule.registry import RuleRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_repo_gruff_py_yaml_references_all_builtin_rules_and_pillars() -> None:
    data = load_gruff_py_yaml(_PROJECT_ROOT / ".gruff-py.yaml")
    definitions = [rule.definition() for rule in RuleRegistry.defaults().all()]

    assert data["selection"]["tiers"] == _unique(
        definition.tier.value for definition in definitions
    )
    assert data["selection"]["pillars"] == _unique(
        definition.pillar.value for definition in definitions
    )
    assert data["selection"]["rules"] == [definition.id for definition in definitions]
    assert set(data["rules"]) == {definition.id for definition in definitions}

    for definition in definitions:
        section = data["rules"][definition.id]
        assert section["enabled"] is definition.default_enabled
        if set(definition.default_thresholds) == {"warning", "error"}:
            assert "thresholds" not in section
            assert section["threshold"] == definition.default_thresholds["error"]
            assert section["severity"] == "error"
        else:
            assert section.get("thresholds", {}) == _plain(definition.default_thresholds)
            assert "threshold" not in section
            assert "severity" not in section
        assert section.get("options", {}) == _plain(definition.default_options)


def _unique(values: Any) -> list[str]:
    return list(dict.fromkeys(values))


def _plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    return value
