import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity.npath_complexity_rule import NPathComplexityRule, npath_for
from gruffpy.rule.context import RuleContext
from gruffpy.source.source_file import SourceFile


def _first_fn(source: str) -> ast.FunctionDef:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function found")


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 200, error: int = 500) -> RuleContext:
    rule = NPathComplexityRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_simple_function_npath_one():
    src = "def f(x):\n    return x + 1\n"
    assert npath_for(_first_fn(src)) == 1


def test_if_else_no_boolops():
    # if-else with simple condition: cond_paths(1) + then(1) + else(1) = 3
    src = "def f(x):\n    if x:\n        return 1\n    else:\n        return 2\n"
    assert npath_for(_first_fn(src)) == 3


def test_if_without_else():
    # cond_paths(1) + then(1) + else(1, implicit) = 3
    src = "def f(x):\n    if x:\n        return 1\n"
    assert npath_for(_first_fn(src)) == 3


def test_boolop_in_condition_adds_paths():
    # `a and b`: BoolOp with 2 values -> 2-1=1 path; but _condition_paths
    # uses max(1, len(values)-1) -> 1. Wait: 1 path means same as no boolop.
    # For `a and b` cond: cond_paths=1 (from BoolOp len(values)-1=1)
    # then=1, else=1 -> total 3
    src = "def f(a, b):\n    if a and b:\n        return 1\n"
    assert npath_for(_first_fn(src)) == 3


def test_for_loop_npath():
    # for: npath(body) + iter_boolops(0) + 1 = 1 + 0 + 1 = 2
    src = "def f(xs):\n    for x in xs:\n        print(x)\n"
    assert npath_for(_first_fn(src)) == 2


def test_sequential_statements_multiply():
    # Two ifs in sequence: 3 * 3 = 9
    src = "def f(x, y):\n    if x:\n        a = 1\n    if y:\n        b = 2\n"
    # plus the final linear stmts contribute 1 each
    # but each `if` returns 3; total = 3 * 3 = 9
    assert npath_for(_first_fn(src)) == 9


def test_try_except_adds_handler_paths():
    # try: 1 (body) + 1 (handler) + 1 = 3
    src = "def f():\n    try:\n        x = 1\n    except ValueError:\n        x = 2\n"
    assert npath_for(_first_fn(src)) == 3


def test_match_npath():
    # match: sum of npath(case body) + 1 = 1+1+1 + 1 = 4
    src = (
        "def f(x):\n"
        "    match x:\n"
        "        case 1:\n            a = 1\n"
        "        case 2:\n            a = 2\n"
        "        case _:\n            a = 0\n"
    )
    assert npath_for(_first_fn(src)) == 4


def test_high_npath_emits_warning():
    # Chain enough sequential ifs to exceed warning threshold 200.
    # Each if = 3 paths. We need 3^n > 200 → n=5 (3^5=243).
    body = "\n".join(f"    if x{i}:\n        a = {i}" for i in range(5))
    args = ", ".join(f"x{i}" for i in range(5))
    src = f"def f({args}):\n{body}\n"
    findings = NPathComplexityRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert findings[0].metadata["npath"] == 243


def test_extreme_npath_capped_at_5000():
    # 8 sequential ifs: 3^8 = 6561 -> capped to 5000.
    body = "\n".join(f"    if x{i}:\n        a = {i}" for i in range(8))
    args = ", ".join(f"x{i}" for i in range(8))
    src = f"def f({args}):\n{body}\n"
    findings = NPathComplexityRule().analyse(_make_unit(src), _ctx())
    assert findings[0].metadata["npath"] == 5000
    assert findings[0].metadata["npathCapped"] is True
    assert findings[0].severity == Severity.ERROR
