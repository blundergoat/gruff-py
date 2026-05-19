import ast
from pathlib import Path

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity.cyclomatic_complexity_rule import (
    CyclomaticComplexityRule,
    cyclomatic_for,
)
from gruffpy.rule.context import RuleContext
from gruffpy.source.source_file import SourceFile

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


def _function_by_name(name: str) -> ast.FunctionDef | ast.AsyncFunctionDef:
    """Locate the named function definition inside the cc_fixture file.

    Args:
        name: Function name to look up in the fixture's parsed AST.

    Returns:
        The matching ``FunctionDef`` / ``AsyncFunctionDef`` node.
    """
    fixture = Path(__file__).resolve().parents[3] / "fixtures" / "complexity" / "cc_fixture.py"
    tree = ast.parse(fixture.read_text())
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name == name
        ):
            return node
    raise AssertionError(f"function {name!r} not found in cc_fixture.py")


@pytest.mark.parametrize(
    ("function_name", "expected"),
    sorted(RADON_GROUND_TRUTH.items()),
    ids=lambda v: v if isinstance(v, str) else None,
)
def test_matches_radon_ground_truth(function_name: str, expected: int) -> None:
    """Cross-check cyclomatic values against radon 6.0.1 on the fixture file.

    Run ``uvx radon cc tests/fixtures/complexity/cc_fixture.py -s`` to refresh
    the ground-truth values in ``tests/fixtures/complexity/radon_ground_truth.md``.

    Args:
        function_name: Function in the cc_fixture file to measure.
        expected: Radon 6.0.1 reference complexity for that function.
    """
    assert cyclomatic_for(_function_by_name(function_name)) == expected


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
