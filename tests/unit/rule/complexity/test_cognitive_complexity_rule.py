"""Cognitive complexity tests (ADR-003).

Each test is a hand-traced application of the SonarSource v1.4 rules.
Numbers in comments show the contributing increments.
"""

import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.complexity.cognitive_complexity_rule import (
    CognitiveComplexityRule,
    cognitive_for,
)
from gruff.rule.context import RuleContext
from gruff.source.source_file import SourceFile


def _first_fn(source: str) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return node
    raise AssertionError("no function found")


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 15, error: int = 30) -> RuleContext:
    rule = CognitiveComplexityRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_simple_function_zero():
    src = "def f(x):\n    return x + 1\n"
    assert cognitive_for(_first_fn(src)) == 0


def test_single_if_one():
    # if at nesting 0 -> B1=1, B2=0 -> total 1
    src = "def f(x):\n    if x > 0:\n        return 1\n    return 0\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_if_else_two():
    # if (1) + else (1) = 2
    src = "def f(x):\n    if x > 0:\n        return 1\n    else:\n        return 0\n"
    assert cognitive_for(_first_fn(src)) == 2


def test_if_elif_else_three():
    # if (1) + elif (1) + else (1) = 3
    src = (
        "def f(x):\n"
        "    if x > 0:\n        return 1\n"
        "    elif x < 0:\n        return -1\n"
        "    else:\n        return 0\n"
    )
    assert cognitive_for(_first_fn(src)) == 3


def test_nested_if_adds_nesting_penalty():
    # outer if at nest=0: B1=1 B2=0
    # inner if at nest=1: B1=1 B2=1 -> total 3
    src = "def f(x, y):\n    if x > 0:\n        if y > 0:\n            return 1\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_for_loop_one():
    src = "def f(xs):\n    for x in xs:\n        print(x)\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_for_with_nested_if():
    # for at 0: 1; if at 1: 1+1=2 -> total 3
    src = "def f(xs):\n    for x in xs:\n        if x:\n            print(x)\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_boolop_single_kind_one():
    # if (1) + BoolOp(and) (1) = 2
    src = "def f(a, b, c):\n    if a and b and c:\n        return 1\n"
    assert cognitive_for(_first_fn(src)) == 2


def test_boolop_mixed_kinds_two():
    # if (1) + BoolOp(or, [BoolOp(and, [a, b]), c]) -> 2 BoolOp nodes = 2
    # Total = 1 (if) + 2 (boolops) = 3
    src = "def f(a, b, c):\n    if a and b or c:\n        return 1\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_try_except_one_handler():
    # try contributes 0; each except = 1 + nesting (here 0) = 1
    src = "def f():\n    try:\n        pass\n    except ValueError:\n        pass\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_try_two_excepts_two():
    src = (
        "def f():\n"
        "    try:\n        pass\n"
        "    except ValueError:\n        pass\n"
        "    except KeyError:\n        pass\n"
    )
    assert cognitive_for(_first_fn(src)) == 2


def test_ternary_one():
    src = "def f(x):\n    return 1 if x else 0\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_match_one():
    # match at 0 = 1+0 = 1; cases do NOT add B1 per ADR-003
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case 1:\n            return 'one'\n"
        "        case 2:\n            return 'two'\n"
    )
    assert cognitive_for(_first_fn(src)) == 1


def test_recursion_adds_one():
    src = "def factorial(n):\n    if n <= 1:\n        return 1\n    return n * factorial(n - 1)\n"
    # if (1) + recursion (1) = 2
    assert cognitive_for(_first_fn(src)) == 2


def test_deep_nesting_compounds():
    # if at 0: 1
    # for at 1: 1+1 = 2
    # if at 2: 1+2 = 3
    # Total: 6
    src = (
        "def f(xs):\n"
        "    if xs:\n"
        "        for x in xs:\n"
        "            if x > 0:\n"
        "                print(x)\n"
    )
    assert cognitive_for(_first_fn(src)) == 6


def test_nested_function_does_not_inflate_outer():
    # Outer is empty (just defines + returns inner); inner has its own
    # complexity. cognitive_for(outer) should NOT include inner's body.
    src = (
        "def outer():\n"
        "    def inner(x):\n"
        "        if x:\n"
        "            return 1\n"
        "        return 0\n"
        "    return inner\n"
    )
    outer = _first_fn(src)
    assert cognitive_for(outer) == 0


def test_high_score_emits_warning_finding():
    # 6 pairs of nested if -> 6 * 3 = 18 cognitive points (> 15 warning)
    body = "\n".join(f"    if x{i}:\n        if y{i}:\n            return {i}" for i in range(6))
    args = ", ".join(sum([[f"x{i}", f"y{i}"] for i in range(6)], []))
    src = f"def f({args}):\n{body}\n"
    findings = CognitiveComplexityRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert findings[0].metadata["cognitive"] == 18


def test_definition_uses_default_thresholds():
    d = CognitiveComplexityRule().definition()
    assert d.id == "complexity.cognitive"
    assert d.default_thresholds == {"warning": 15, "error": 30}
