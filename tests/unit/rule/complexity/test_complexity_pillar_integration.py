"""Cumulative integration tests covering complexity-pillar registry and metadata behavior."""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.composite_finding_factory import CompositeFindingFactory
from gruffpy.source.source_file import SourceFile

COMPLEXITY_RULE_IDS = {
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.halstead-volume",
    "complexity.maintainability-index",
    "complexity.nesting-depth",
    "complexity.npath",
}

COMPLEXITY_FIXTURE = '''
"""Fixture exercising the M03 complexity rules."""


def shallow(x):
    return x + 1


def too_complex(a, b, c, d, e, f):
    if a and b:
        if c or d:
            if e:
                if f:
                    if a > b:
                        if c < d:
                            if e == f:
                                if a + b > c:
                                    if d + e > f:
                                        return 1
    return 0


def too_long():
    x = 1
    x = 2
    x = 3
    x = 4
    x = 5
    x = 6
    x = 7
    x = 8
    x = 9
    x = 10
    x = 11
    x = 12
    x = 13
    x = 14
    x = 15
    x = 16
    x = 17
    x = 18
    x = 19
    x = 20
    x = 21
    x = 22
    x = 23
    x = 24
    x = 25
    x = 26
    x = 27
    x = 28
    x = 29
    x = 30
    x = 31
    x = 32
    return x


def god_method(a, b, c, d, e, f, g, h):
    """Long + parameter-heavy + complex; should produce a composite."""
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if a > b:
                                        if b > c:
                                            return 1
    if a + b + c + d > 0:
        for i in range(10):
            for j in range(10):
                if i > j:
                    for k in range(10):
                        if k > 0:
                            print(i, j, k)
    return 0
'''


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/integration.py", display_path="integration.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _default_ctx() -> RuleContext:
    # PMD-aligned size defaults are too generous for the compact fixture.
    # Override size.function-length and size.parameter-count so the fixture
    # still produces overlapping size + complexity findings for the
    # design.god-method composite.
    size_test_thresholds = {
        "size.function-length": {"warning": 15, "error": 30},
        "size.parameter-count": {"warning": 5, "error": 8},
    }
    return _ctx_with_threshold_overrides(size_test_thresholds)


def _ctx_with_threshold_overrides(
    overrides: dict[str, dict[str, int]],
) -> RuleContext:
    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=True,
            thresholds=overrides.get(
                rule.definition().id, dict(rule.definition().default_thresholds)
            ),
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def _ctx_for_complexity_metadata() -> RuleContext:
    """Context enabling only complexity rules, with reversed MI thresholds."""

    def thresholds_for(rule_id: str) -> dict[str, int]:
        """Return the per-rule threshold pair used to force findings for every complexity rule.

        Maintainability-index inverts direction (lower is worse) so warning=101 guarantees the
        clamped MI=100 trips the rule; other complexity rules use warning=0 to fire on any value.

        Args:
            rule_id: Canonical rule id to compute thresholds for.

        Returns:
            Threshold mapping suitable for ``RuleSettings.thresholds``; empty dict
            for rule ids outside ``COMPLEXITY_RULE_IDS`` (they stay disabled).
        """
        if rule_id == "complexity.maintainability-index":
            return {"warning": 101, "error": 0}
        if rule_id in COMPLEXITY_RULE_IDS:
            return {"warning": 0, "error": 9999}
        return {}

    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=rule.definition().id in COMPLEXITY_RULE_IDS,
            thresholds=thresholds_for(rule.definition().id),
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_defaults_includes_all_six_complexity_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    assert COMPLEXITY_RULE_IDS.issubset(ids)


def test_complexity_rules_emit_findings_on_fixture():
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    rule_ids = {f.rule_id for f in findings}
    # too_complex should fire at minimum cyclomatic, cognitive, nesting-depth,
    # and npath.
    assert "complexity.cyclomatic" in rule_ids
    assert "complexity.cognitive" in rule_ids
    assert "complexity.nesting-depth" in rule_ids


_METADATA_FIXTURE_SRC = """
def sample(a, b):
    if a + 1 > b - 1:
        if a and b:
            return a * b
    return a + b
"""


def _complexity_findings_with_metadata_ctx() -> list:
    findings = RuleRegistry.defaults().analyse(
        [_make_unit(_METADATA_FIXTURE_SRC)], _ctx_for_complexity_metadata()
    )
    return [f for f in findings if f.rule_id in COMPLEXITY_RULE_IDS]


def test_complexity_metadata_covers_all_complexity_rules():
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert COMPLEXITY_RULE_IDS.issubset({f.rule_id for f in complexity_findings})


def test_complexity_findings_carry_numeric_measured_value():
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert all(isinstance(f.metadata["measuredValue"], int | float) for f in complexity_findings)


def test_complexity_findings_carry_warning_threshold_type():
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert all(f.metadata["thresholdType"] == "warning" for f in complexity_findings)


def test_above_threshold_complexity_findings_carry_above_direction():
    complexity_findings = [
        f
        for f in _complexity_findings_with_metadata_ctx()
        if f.rule_id != "complexity.maintainability-index"
    ]
    assert all(f.metadata["threshold"] == 0 for f in complexity_findings)
    assert all(f.metadata["thresholdDirection"] == "above" for f in complexity_findings)


def test_maintainability_index_finding_carries_below_direction():
    mi_findings = [
        f
        for f in _complexity_findings_with_metadata_ctx()
        if f.rule_id == "complexity.maintainability-index"
    ]
    assert all(f.metadata["threshold"] == 101 for f in mi_findings)
    assert all(f.metadata["thresholdDirection"] == "below" for f in mi_findings)


def test_design_god_method_synthesises_on_overlap():
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    composites = CompositeFindingFactory().synthesise(findings)
    god_methods = [f for f in composites if f.rule_id == "design.god-method"]
    assert god_methods, "expected at least one design.god-method composite"
    # god_method symbol should be among the composites
    symbols = {f.symbol for f in god_methods}
    assert "god_method" in symbols


_COMPLEXITY_RULES_FOR_SHALLOW = (
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.nesting-depth",
    "complexity.npath",
)


def test_shallow_function_no_complexity_findings():
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    shallow_complexity_findings = [
        f for f in findings if f.symbol == "shallow" and f.rule_id in _COMPLEXITY_RULES_FOR_SHALLOW
    ]
    assert shallow_complexity_findings == []


def test_findings_deterministic_across_two_runs():
    unit_a = _make_unit(COMPLEXITY_FIXTURE)
    unit_b = _make_unit(COMPLEXITY_FIXTURE)
    ctx = _default_ctx()
    registry = RuleRegistry.defaults()
    a = registry.analyse([unit_a], ctx)
    b = registry.analyse([unit_b], ctx)
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b]


def test_maintainability_index_uses_maintainability_pillar():
    # Build a function with low MI -> finding pillar = maintainability
    body = "\n".join(
        f"    if a{i} + b{i} == c{i} - d{i}:\n        x = a{i} * b{i}" for i in range(40)
    )
    src = f"def f():\n{body}\n    return x\n"
    findings = RuleRegistry.defaults().analyse([_make_unit(src)], _default_ctx())
    mi_findings = [f for f in findings if f.rule_id == "complexity.maintainability-index"]
    assert mi_findings, "expected at least one maintainability-index finding"
    assert all(f.pillar.value == "maintainability" for f in mi_findings)
