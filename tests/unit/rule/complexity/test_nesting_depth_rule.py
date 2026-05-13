import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.complexity.nesting_depth_rule import NestingDepthRule, nesting_depth_for
from gruff.rule.context import RuleContext
from gruff.source.source_file import SourceFile


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
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 4, error: int = 6) -> RuleContext:
    rule = NestingDepthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_no_nesting_depth_zero():
    src = "def f():\n    return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 0


def test_single_if_depth_one():
    src = "def f(x):\n    if x:\n        return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 1


def test_nested_if_depth_two():
    src = "def f(x, y):\n    if x:\n        if y:\n            return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_for_inside_if_depth_two():
    src = "def f(xs):\n    if xs:\n        for x in xs:\n            print(x)\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_try_except_increments_depth():
    src = (
        "def f():\n"
        "    try:\n"
        "        if x:\n"
        "            pass\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    # try at depth 1; if inside try at depth 2
    assert nesting_depth_for(_first_fn(src)) == 2


def test_match_increments_depth():
    src = "def f(x):\n    match x:\n        case 1:\n            if x:\n                return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_with_block_increments_depth():
    src = "def f():\n    with open('x') as f:\n        if f:\n            return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_deeply_nested_emits_warning():
    # 5-deep: if/if/if/if/if
    src = (
        "def f(a, b, c, d, e):\n"
        "    if a:\n"
        "        if b:\n"
        "            if c:\n"
        "                if d:\n"
        "                    if e:\n"
        "                        return 1\n"
    )
    findings = NestingDepthRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert findings[0].metadata["depth"] == 5


def test_extremely_nested_emits_error():
    src = (
        "def f():\n"
        + "\n".join("    " * i + f"if x{i}:" for i in range(1, 9))
        + "\n        "
        + "    " * 7
        + "return 1\n"
    )
    findings = NestingDepthRule().analyse(_make_unit(src), _ctx())
    assert findings[0].severity == Severity.ERROR


def test_nested_function_evaluated_separately():
    src = (
        "def outer():\n"
        "    def inner():\n"
        "        if x:\n"
        "            if y:\n"
        "                if z:\n"
        "                    if w:\n"
        "                        if v:\n"
        "                            return 1\n"
        "    return inner\n"
    )
    findings = NestingDepthRule().analyse(_make_unit(src), _ctx())
    symbols = {f.symbol for f in findings}
    assert "outer.inner" in symbols
    # outer itself has no nested control flow -> no finding
    assert "outer" not in symbols


def test_definition_uses_default_thresholds():
    d = NestingDepthRule().definition()
    assert d.id == "complexity.nesting-depth"
    assert d.default_thresholds == {"warning": 4, "error": 6}
