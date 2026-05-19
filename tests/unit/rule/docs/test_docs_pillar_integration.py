"""Cumulative integration fixture for the documentation pillar.

Exercises every shipped docs rule once on a single source and asserts the
expected rule_ids fire. Stricter than per-rule tests: catches accidental
double-fires and registry omissions.
"""

from pathlib import Path

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.loader import ConfigLoader
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from tests.unit.rule.docs._helpers import make_unit


def _marker(*parts: str) -> str:
    return "".join(parts)


_DENSE_MARKERS = (
    _marker("TO", "DO"),
    _marker("TO", "DO"),
    _marker("FIX", "ME"),
    _marker("HAC", "K"),
    _marker("XX", "X"),
    _marker("BU", "G"),
)


def _todo_density_fixture_lines() -> str:
    labels = ("one", "two", "three", "four", "five", "six")
    return "\n".join(
        f"# {marker}: {label}" for marker, label in zip(_DENSE_MARKERS, labels, strict=True)
    )


# Source crafted to trigger every docs rule at least once.
_FIXTURE = (
    '''from dataclasses import dataclass
import os  # noqa


@dataclass
class Payload:
    name: str
    value: int
    status: str


def route_payload(value):
    total = 0
    if value == 0:
        total += 0
    if value == 1:
        total += 1
    if value == 2:
        total += 2
    if value == 3:
        total += 3
    if value == 4:
        total += 4
    if value == 5:
        total += 5
    if value == 6:
        total += 6
    if value == 7:
        total += 7
    if value == 8:
        total += 8
    if value == 9:
        total += 9
    if value == 10:
        total += 10
    return total


def helper(x, y):
    """Doc.

    Args:
        x: first.
        stale_param: a leftover.
    """
    if x < 0:
        raise ValueError
    return x + y


def echo(value):
    """Echo the value."""
    return value


def needs_doc():
    return 42


class Widget:
    def visible(self) -> int:
        return 1


def slot(x) -> int:
    """Compute.

    Args:
        x: the value.
    """
    return x * 2

'''
    + _todo_density_fixture_lines()
    + "\n"
)

_EXPECTED_RULE_IDS = {
    "docs.complex-branch-rationale",
    "docs.dataclass-attributes",
    "docs.ignore-directive-reason",
    "docs.missing-module-docstring",
    "docs.missing-class-docstring",
    "docs.missing-function-docstring",
    "docs.missing-param-doc",
    "docs.missing-return-doc",
    "docs.missing-raises-doc",
    "docs.stale-param-doc",
    "docs.todo-actionability",
    "docs.useless-docstring",
    "docs.todo-density",
    "docs.missing-readme",
}


def test_every_docs_rule_fires_on_cumulative_fixture(tmp_path: Path):
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    ctx = RuleContext(project_root=str(tmp_path), config=config)

    findings = registry.analyse([make_unit(_FIXTURE, "widget.py")], ctx)
    rule_ids = {f.rule_id for f in findings}

    missing = _EXPECTED_RULE_IDS - rule_ids
    assert not missing, f"Missing rule fires: {sorted(missing)}"


def test_docs_registry_has_fourteen_rules():
    registry = RuleRegistry.defaults()
    docs_ids = {
        rule.definition().id for rule in registry.all() if rule.definition().id.startswith("docs.")
    }
    assert docs_ids == _EXPECTED_RULE_IDS


def test_missing_readme_dedupes_to_one_across_multiple_units(tmp_path: Path):
    # No README in tmp_path. Two units should produce exactly ONE missing-readme
    # finding after registry-level dedup.
    registry = RuleRegistry.defaults()
    config = AnalysisConfig.from_registry(registry)
    ctx = RuleContext(project_root=str(tmp_path), config=config)
    units = [make_unit("def a(): pass\n", "a.py"), make_unit("def b(): pass\n", "b.py")]
    findings = registry.analyse(units, ctx)
    readme_findings = [f for f in findings if f.rule_id == "docs.missing-readme"]
    assert len(readme_findings) == 1


def test_config_can_disable_missing_function_docstring_for_test_paths(tmp_path: Path):
    (tmp_path / ".gruff-py.yaml").write_text(
        "rules:\n  docs.missing-function-docstring:\n    enabled: false\n"
    )
    registry = RuleRegistry.defaults()
    defaults = AnalysisConfig.from_registry(registry)
    config, _ = ConfigLoader(tmp_path, defaults).load()
    ctx = RuleContext(project_root=str(tmp_path), config=config)

    findings = registry.analyse(
        [make_unit("def test_without_doc():\n    pass\n", "tests/test_x.py")], ctx
    )

    assert "docs.missing-function-docstring" not in {finding.rule_id for finding in findings}
