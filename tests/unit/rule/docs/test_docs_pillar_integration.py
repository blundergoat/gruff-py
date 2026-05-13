"""Cumulative integration fixture for the documentation pillar.

Exercises every shipped docs rule once on a single source and asserts the
expected rule_ids fire. Stricter than per-rule tests: catches accidental
double-fires and registry omissions.
"""

from pathlib import Path

from gruff.config.analysis_config import AnalysisConfig
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from tests.unit.rule.docs._helpers import make_unit

# Source crafted to trigger every docs rule at least once.
_FIXTURE = '''def helper(x, y):
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


# TODO: one
# TODO: two
# FIXME: three
# HACK: four
# XXX: five
# BUG: six
'''

_EXPECTED_RULE_IDS = {
    "docs.missing-module-docstring",
    "docs.missing-class-docstring",
    "docs.missing-function-docstring",
    "docs.missing-param-doc",
    "docs.missing-return-doc",
    "docs.missing-raises-doc",
    "docs.stale-param-doc",
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


def test_docs_registry_has_ten_rules():
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
