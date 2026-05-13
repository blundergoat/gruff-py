import ast
from pathlib import Path

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.complexity.cyclomatic_complexity_rule import (
    CyclomaticComplexityRule,
    cyclomatic_for,
)
from gruff.rule.context import RuleContext
from gruff.source.source_file import SourceFile

RADON_GROUND_TRUTH = {
    "simple": 1,
    "with_branches": 3,
    "with_loop": 3,
    "with_boolops": 4,
    "with_match": 3,
    "with_comprehension": 3,
    "t1": 2,
    "t2": 3,
    "a1": 2,
    "a2": 3,
}


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 10, error: int = 20) -> RuleContext:
    rule = CyclomaticComplexityRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_matches_radon_ground_truth():
    """Cross-check cyclomatic values against radon 6.0.1 on the fixture file.

    Run `uvx radon cc tests/fixtures/complexity/cc_fixture.py -s` to refresh
    the ground-truth values in `tests/fixtures/complexity/radon_ground_truth.md`.
    """
    fixture = Path(__file__).resolve().parents[3] / "fixtures" / "complexity" / "cc_fixture.py"
    tree = ast.parse(fixture.read_text())
    actual: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            actual[node.name] = cyclomatic_for(node)
    for name, expected in RADON_GROUND_TRUTH.items():
        assert actual[name] == expected, (
            f"{name}: gruff={actual[name]} but radon ground truth={expected}"
        )


def test_simple_function_returns_1():
    src = "def f():\n    return 1\n"
    findings = CyclomaticComplexityRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_high_complexity_emits_warning():
    # Build a function with 11 if-statements -> cc = 12 (> default warning 10)
    body = "\n".join([f"    if x == {i}: return {i}" for i in range(11)])
    src = f"def f(x):\n{body}\n"
    findings = CyclomaticComplexityRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.WARNING
    assert f.metadata["complexity"] == 12
    assert f.symbol == "f"


def test_above_error_threshold_emits_error():
    body = "\n".join([f"    if x == {i}: return {i}" for i in range(25)])
    src = f"def f(x):\n{body}\n"
    findings = CyclomaticComplexityRule().analyse(_make_unit(src), _ctx())
    assert findings[0].severity == Severity.ERROR


def test_nested_function_emits_separate_finding():
    inner = "\n".join([f"        if x == {i}: return {i}" for i in range(11)])
    src = f"def outer(x):\n    def inner(x):\n{inner}\n    return inner\n"
    findings = CyclomaticComplexityRule().analyse(_make_unit(src), _ctx())
    symbols = {f.symbol for f in findings}
    assert "outer.inner" in symbols
    # outer itself is too simple at default thresholds: cc=1
    assert "outer" not in symbols


def test_method_symbol_qualified():
    body = "\n".join([f"        if x == {i}: return {i}" for i in range(11)])
    src = f"class C:\n    def m(self, x):\n{body}\n"
    findings = CyclomaticComplexityRule().analyse(_make_unit(src), _ctx())
    assert findings[0].symbol == "C.m"


def test_definition_uses_default_thresholds():
    d = CyclomaticComplexityRule().definition()
    assert d.id == "complexity.cyclomatic"
    assert d.default_thresholds == {"warning": 10, "error": 20}
