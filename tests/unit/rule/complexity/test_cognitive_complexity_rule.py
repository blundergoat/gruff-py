"""Cognitive complexity tests (ADR-003).

Each test is a hand-traced application of the SonarSource v1.4 rules.
Numbers in comments show the contributing increments.
"""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity.cognitive_complexity_rule import (
    CognitiveComplexityRule,
    cognitive_for,
)
from gruffpy.rule.context import RuleContext
from gruffpy.source.source_file import SourceFile


def _first_fn(source: str) -> ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda:
    """Return the first top-level function definition in source, sync or async.

    Args:
        source: Python source to parse.

    Returns:
        That function definition.

    Raises:
        AssertionError: The source has no top-level function.
    """
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return node
    raise AssertionError("no function found")


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``x.py``.

    Args:
        source: Python source to parse.

    Returns:
        The analysis unit.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 15) -> RuleContext:
    """Build a rule context with the cognitive complexity rule enabled at an error threshold.

    Args:
        threshold: Score the rule allows before it reports; defaults to 15.

    Returns:
        The rule context.
    """
    rule = CognitiveComplexityRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_simple_function_zero():
    """Score a function with no branches at 0."""
    src = "def f(x):\n    return x + 1\n"
    assert cognitive_for(_first_fn(src)) == 0


def test_single_if_one():
    """Score a single top-level ``if`` at 1."""
    # if at nesting 0 -> B1=1, B2=0 -> total 1
    src = "def f(x):\n    if x > 0:\n        return 1\n    return 0\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_if_else_two():
    """Score an ``if`` with an ``else`` at 2."""
    # if (1) + else (1) = 2
    src = "def f(x):\n    if x > 0:\n        return 1\n    else:\n        return 0\n"
    assert cognitive_for(_first_fn(src)) == 2


def test_if_elif_else_three():
    """Score an ``if``, ``elif`` and ``else`` chain at 3."""
    # if (1) + elif (1) + else (1) = 3
    src = "def f(x):\n    if x > 0:\n        return 1\n    elif x < 0:\n        return -1\n    else:\n        return 0\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_nested_if_adds_nesting_penalty():
    """Score an ``if`` nested inside another ``if`` at 3."""
    # outer if at nest=0: B1=1 B2=0
    # inner if at nest=1: B1=1 B2=1 -> total 3
    src = "def f(x, y):\n    if x > 0:\n        if y > 0:\n            return 1\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_for_loop_one():
    """Score a single ``for`` loop at 1."""
    src = "def f(xs):\n    for x in xs:\n        print(x)\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_for_with_nested_if():
    """Score an ``if`` nested inside a ``for`` loop at 3."""
    # for at 0: 1; if at 1: 1+1=2 -> total 3
    src = "def f(xs):\n    for x in xs:\n        if x:\n            print(x)\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_boolop_single_kind_one():
    """Score an ``if`` whose condition chains only ``and`` at 2."""
    # if (1) + BoolOp(and) (1) = 2
    src = "def f(a, b, c):\n    if a and b and c:\n        return 1\n"
    assert cognitive_for(_first_fn(src)) == 2


def test_boolop_mixed_kinds_two():
    """Score an ``if`` whose condition mixes ``and`` with ``or`` at 3."""
    # if (1) + BoolOp(or, [BoolOp(and, [a, b]), c]) -> 2 BoolOp nodes = 2
    # Total = 1 (if) + 2 (boolops) = 3
    src = "def f(a, b, c):\n    if a and b or c:\n        return 1\n"
    assert cognitive_for(_first_fn(src)) == 3


def test_try_except_one_handler():
    """Score a ``try`` with one ``except`` handler at 1."""
    # try contributes 0; each except = 1 + nesting (here 0) = 1
    src = "def f():\n    try:\n        pass\n    except ValueError:\n        pass\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_try_two_excepts_two():
    """Score a ``try`` with two ``except`` handlers at 2."""
    src = "def f():\n    try:\n        pass\n    except ValueError:\n        pass\n    except KeyError:\n        pass\n"
    assert cognitive_for(_first_fn(src)) == 2


def test_ternary_one():
    """Score a conditional expression at 1."""
    src = "def f(x):\n    return 1 if x else 0\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_match_one():
    """Score a ``match`` with two cases at 1."""
    # match at 0 = 1+0 = 1; cases do NOT add B1 per ADR-003
    src = "def f(x):\n    match x:\n        case 1:\n            return 'one'\n        case 2:\n            return 'two'\n"
    assert cognitive_for(_first_fn(src)) == 1


def test_recursion_adds_one():
    """Score a recursive function with one ``if`` at 2."""
    src = "def factorial(n):\n    if n <= 1:\n        return 1\n    return n * factorial(n - 1)\n"
    # if (1) + recursion (1) = 2
    assert cognitive_for(_first_fn(src)) == 2


def test_deep_nesting_compounds():
    """Score an ``if`` inside a ``for`` loop inside another ``if`` at 6."""
    # if at 0: 1
    # for at 1: 1+1 = 2
    # if at 2: 1+2 = 3
    # Total: 6
    src = "def f(xs):\n    if xs:\n        for x in xs:\n            if x > 0:\n                print(x)\n"
    assert cognitive_for(_first_fn(src)) == 6


def test_nested_function_does_not_inflate_outer():
    """Score an outer function at 0 when only its nested function has branches."""
    # Outer is empty (just defines + returns inner); inner has its own
    # complexity. cognitive_for(outer) should NOT include inner's body.
    src = "def outer():\n    def inner(x):\n        if x:\n            return 1\n        return 0\n    return inner\n"
    outer = _first_fn(src)
    assert cognitive_for(outer) == 0


def test_score_just_over_threshold_is_a_lower_band_notice():
    """Report a score of 18 against a threshold of 15 as one advisory finding in the lower limit band."""
    # 6 pairs of nested if -> 6 * 3 = 18 cognitive points: over the threshold of 15, under one and a half times it
    body = "\n".join(f"    if x{i}:\n        if y{i}:\n            return {i}" for i in range(6))
    args = ", ".join(sum([[f"x{i}", f"y{i}"] for i in range(6)], []))
    src = f"def f({args}):\n{body}\n"
    findings = CognitiveComplexityRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.ADVISORY
    assert findings[0].metadata["limitBand"] == "lower"
    assert findings[0].metadata["cognitive"] == 18
