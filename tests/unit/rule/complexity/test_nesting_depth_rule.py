import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity.nesting_depth_rule import NestingDepthRule, nesting_depth_for
from gruffpy.rule.context import RuleContext
from gruffpy.source.source_file import SourceFile


def _first_fn(source: str) -> ast.FunctionDef:
    """Return the first top-level, non-async function definition in source.

    Args:
        source: Python source to parse.

    Returns:
        That function definition.

    Raises:
        AssertionError: The source has no top-level, non-async function.
    """
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
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


def _ctx(threshold: int = 4) -> RuleContext:
    """Build a rule context with the nesting depth rule enabled at an error threshold.

    Args:
        threshold: Depth the rule allows before it reports; defaults to 4.

    Returns:
        The rule context.
    """
    rule = NestingDepthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_no_nesting_depth_zero():
    """Measure depth 0 for a function with no control-flow blocks."""
    src = "def f():\n    return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 0


def test_single_if_depth_one():
    """Measure depth 1 for a single ``if``."""
    src = "def f(x):\n    if x:\n        return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 1


def test_nested_if_depth_two():
    """Measure depth 2 for an ``if`` inside another ``if``."""
    src = "def f(x, y):\n    if x:\n        if y:\n            return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_for_inside_if_depth_two():
    """Measure depth 2 for a ``for`` loop inside an ``if``."""
    src = "def f(xs):\n    if xs:\n        for x in xs:\n            print(x)\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_try_except_increments_depth():
    """Measure depth 2 for an ``if`` inside a ``try`` block."""
    src = "def f():\n    try:\n        if x:\n            pass\n    except ValueError:\n        pass\n"
    # try at depth 1; if inside try at depth 2
    assert nesting_depth_for(_first_fn(src)) == 2


def test_match_increments_depth():
    """Measure depth 2 for an ``if`` inside a ``match`` case."""
    src = "def f(x):\n    match x:\n        case 1:\n            if x:\n                return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_with_block_increments_depth():
    """Measure depth 2 for an ``if`` inside a ``with`` block."""
    src = "def f():\n    with open('x') as f:\n        if f:\n            return 1\n"
    assert nesting_depth_for(_first_fn(src)) == 2


def test_depth_just_over_threshold_is_a_lower_band_notice():
    """Report depth 5 against a threshold of 4 as one advisory finding in the lower limit band."""
    # 5-deep: if/if/if/if/if, over the threshold but under one and a half times it
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
    assert findings[0].severity == Severity.ADVISORY
    assert findings[0].metadata["limitBand"] == "lower"
    assert findings[0].metadata["depth"] == 5


def test_extremely_nested_emits_error():
    """Report error severity for eight nested ``if`` statements against a threshold of 4."""
    src = "def f():\n" + "\n".join("    " * i + f"if x{i}:" for i in range(1, 9)) + "\n        " + "    " * 7 + "return 1\n"
    findings = NestingDepthRule().analyse(_make_unit(src), _ctx())
    assert findings[0].severity == Severity.ERROR


def test_nested_function_evaluated_separately():
    """Report a deeply nested inner function as ``outer.inner`` and leave its flat outer function unreported."""
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


def test_elif_chain_is_one_level_not_one_per_branch():
    """Measure depth 2 for an ``if``, ``elif`` and ``else`` chain whose four branches each hold one more ``if``."""
    # Four peer branches, each holding one more if: depth 2, not the 5 an elif-as-nesting count would give.
    src = (
        "def f(x, y):\n"
        "    if x == 1:\n        if y:\n            return 1\n"
        "    elif x == 2:\n        if y:\n            return 2\n"
        "    elif x == 3:\n        if y:\n            return 3\n"
        "    else:\n        if y:\n            return 4\n"
        "    return 0\n"
    )
    assert nesting_depth_for(_first_fn(src)) == 2


def test_nested_ifs_still_count_each_level():
    """Measure depth 3 for two nested ``if`` statements inside an ``else`` block."""
    # The close control: an if inside an else block is a real level, so three nested ifs stay depth 3.
    src = "def f(a, b, c):\n    if a:\n        pass\n    else:\n        if b:\n            if c:\n                return 1\n    return 0\n"
    assert nesting_depth_for(_first_fn(src)) == 3
