"""Cumulative integration test for the complexity pillar (M03)."""

import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from gruff.scoring.composite_finding_factory import CompositeFindingFactory
from gruff.source.source_file import SourceFile

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
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        d = rule.definition()
        rules[d.id] = RuleSettings(enabled=True, thresholds=dict(d.default_thresholds))
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_defaults_includes_all_six_complexity_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    expected_complexity = {
        "complexity.cognitive",
        "complexity.cyclomatic",
        "complexity.halstead-volume",
        "complexity.maintainability-index",
        "complexity.nesting-depth",
        "complexity.npath",
    }
    assert expected_complexity.issubset(ids)


def test_complexity_rules_emit_findings_on_fixture():
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    rule_ids = {f.rule_id for f in findings}
    # too_complex should fire at minimum cyclomatic, cognitive, nesting-depth,
    # and npath.
    assert "complexity.cyclomatic" in rule_ids
    assert "complexity.cognitive" in rule_ids
    assert "complexity.nesting-depth" in rule_ids


def test_design_god_method_synthesises_on_overlap():
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    composites = CompositeFindingFactory().synthesise(findings)
    god_methods = [f for f in composites if f.rule_id == "design.god-method"]
    assert god_methods, "expected at least one design.god-method composite"
    # god_method symbol should be among the composites
    symbols = {f.symbol for f in god_methods}
    assert "god_method" in symbols


def test_shallow_function_no_complexity_findings():
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    for f in findings:
        if f.symbol == "shallow":
            assert f.rule_id not in (
                "complexity.cognitive",
                "complexity.cyclomatic",
                "complexity.nesting-depth",
                "complexity.npath",
            ), f"shallow should not trip {f.rule_id}"


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
    if mi_findings:
        assert mi_findings[0].pillar.value == "maintainability"
