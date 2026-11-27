import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.waste.unreachable_code_rule import UnreachableCodeRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap the result as the x.py unit.

    Args:
        source: Python module source to parse.

    Returns:
        An analysis unit displayed as x.py whose non-root tree nodes carry parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # Parsed AST nodes accept extra attributes for fixture metadata.
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    """Build a context whose config holds only the unreachable-code rule's settings, with that rule enabled.

    Returns:
        A context rooted at / with that one-rule config.
    """
    rule = UnreachableCodeRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True)},
        ),
    )


def test_no_unreachable_code_returns_empty():
    """Report nothing for a function that assigns a value and returns it.

    Returns:
        None. Asserts that assigning a value and then returning it produces no unreachable-code findings.
    """
    src = "def f():\n    x = 1\n    return x\n"
    assert UnreachableCodeRule().analyse(_make_unit(src), _ctx()) == []


def test_after_return_is_unreachable():
    """Report one warning at the statement after a return, recording return as the terminator.

    Returns:
        None. Asserts that the statement after return produces one warning at that statement and records return as the terminator.
    """
    src = "def f():\n    return 1\n    x = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.WARNING
    assert findings[0].metadata["terminator"] == "return"
    assert findings[0].line == 3


def test_after_raise_is_unreachable():
    """Report one finding for a statement after a raise, recording raise as the terminator.

    Returns:
        None. Asserts that the fixture with a statement after raise produces one finding with raise as the terminator.
    """
    src = "def f():\n    raise ValueError()\n    x = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["terminator"] == "raise"


def test_after_continue_in_loop():
    """Report one finding for a statement after continue in a loop, recording continue as the terminator.

    Returns:
        None. Asserts that the loop fixture produces one finding with continue as the terminator.
    """
    src = "def f():\n    for x in [1]:\n        continue\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["terminator"] == "continue"


def test_after_break_in_loop():
    """Report one finding for a statement after break in a loop, recording break as the terminator.

    Returns:
        None. Asserts that the loop fixture produces one finding with break as the terminator.
    """
    src = "def f():\n    for x in [1]:\n        break\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["terminator"] == "break"


def test_only_first_unreachable_reported_per_block():
    """Report one finding for three statements after a return in the same block.

    Returns:
        None. Asserts that three statements after a return in the same block produce one finding.
    """
    src = "def f():\n    return 1\n    x = 2\n    y = 3\n    z = 4\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1


def test_unreachable_in_branch_separate_from_other_branch():
    """Report two findings when each branch of an if has a statement after its return.

    Returns:
        None. Asserts that the two-branch fixture produces two findings when both branches have statements after return.
    """
    src = "def f(x):\n    if x:\n        return 1\n        a = 2\n    else:\n        return 3\n        b = 4\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 2


def test_return_at_end_of_block_is_fine():
    """Report nothing when one return ends an if body and another ends the function.

    Returns:
        None. Asserts that a return ending the if body and another ending the function produce no findings.
    """
    src = "def f(x):\n    if x:\n        return 1\n    return 0\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_false_body_is_unreachable():
    """Report one warning at the body of if False, naming the literal-false condition and its line.

    Returns:
        None. Asserts that if False produces one warning at its body and records the literal-false cause and condition line.
    """
    src = "def f():\n    if False:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.WARNING
    assert finding.line == 3
    assert finding.metadata["cause"] == "literal-false-condition"
    assert finding.metadata["causeLine"] == 2


def test_while_false_body_is_unreachable():
    """Report one finding for the body of while False, naming the literal-false condition.

    Returns:
        None. Asserts that the while False fixture produces one finding with a literal-false condition as its cause.
    """
    src = "def f():\n    while False:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_true_else_branch_is_unreachable():
    """Report one finding at the else body of if True, naming the literal-true condition and its line.

    Returns:
        None. Asserts that if True produces one finding at its else body and records the literal-true cause and condition line.
    """
    src = "def f():\n    if True:\n        x = 1\n    else:\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.line == 5
    assert finding.metadata["cause"] == "literal-true-condition"
    assert finding.metadata["causeLine"] == 2


def test_if_zero_body_is_unreachable():
    """Report one finding for the body of if 0, naming the literal-false condition.

    Returns:
        None. Asserts that the if 0 fixture produces one finding with a literal-false condition as its cause.
    """
    src = "def f():\n    if 0:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_one_else_branch_is_unreachable():
    """Report one finding for the else body of if 1, naming the literal-true condition.

    Returns:
        None. Asserts that the if 1 fixture with an else branch produces one finding with a literal-true condition as its cause.
    """
    src = "def f():\n    if 1:\n        x = 1\n    else:\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-true-condition"


def test_if_none_body_is_unreachable():
    """Report one finding for the body of if None, naming the literal-false condition.

    Returns:
        None. Asserts that the if None fixture produces one finding with a literal-false condition as its cause.
    """
    src = "def f():\n    if None:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_empty_string_body_is_unreachable():
    """Report one finding for the body of an if with an empty-string condition, naming the literal-false condition.

    Returns:
        None. Asserts that an if with an empty-string condition produces one finding with a literal-false condition as its cause.
    """
    src = 'def f():\n    if "":\n        x = 1\n'
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-false-condition"


def test_if_nonempty_string_else_is_unreachable():
    """Report one finding for the else body of if "x", naming the literal-true condition.

    Returns:
        None. Asserts that if "x" with an else branch produces one finding with a literal-true condition as its cause.
    """
    src = 'def f():\n    if "x":\n        x = 1\n    else:\n        y = 2\n'
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["cause"] == "literal-true-condition"


def test_if_true_without_else_emits_nothing():
    """Report nothing for if True without an else.

    Returns:
        None. Asserts that if True without an else produces no findings.
    """
    src = "def f():\n    if True:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_name_does_not_fire():
    """Report nothing for an if on a local name assigned False.

    Returns:
        None. Asserts that an if on a local name assigned False produces no findings.
    """
    # Dynamic condition; even if the name resolves to False at runtime, the rule stays out of it. Conservative scope.
    src = "def f():\n    FLAG = False\n    if FLAG:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_call_does_not_fire():
    """Report nothing for an if on the call bool().

    Returns:
        None. Asserts that an if using bool() as its condition produces no findings.
    """
    src = "def f():\n    if bool():\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_comparison_does_not_fire():
    """Report nothing for an if on the constant comparison 1 == 1.

    Returns:
        None. Asserts that the fixture using 1 == 1 as its if condition produces no findings.
    """
    src = "def f():\n    if 1 == 1:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_not_false_does_not_fire():
    """Report nothing for if not False with an else branch.

    Returns:
        None. Asserts that if not False with an else branch produces no findings.
    """
    # not False is True at runtime but isn't a syntactic constant.
    src = "def f():\n    if not False:\n        x = 1\n    else:\n        y = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_boolop_does_not_fire():
    """Report nothing for if True and False.

    Returns:
        None. Asserts that if True and False produces no findings.
    """
    src = "def f():\n    if True and False:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_if_attribute_does_not_fire():
    """Report nothing for an if on the attribute os.environ.

    Returns:
        None. Asserts that analysis returns an empty findings list for the attribute condition.
    """
    # Attribute truth values are not inferred, so os.environ produces no unreachable-code finding.
    src = "import os\ndef f():\n    if os.environ:\n        x = 1\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings == []


def test_literal_false_only_first_stmt_reported():
    """Report one finding, at the first statement, for three statements under if False.

    Returns:
        None. Checks the finding count and the line of the first unreachable statement.
    """
    src = "def f():\n    if False:\n        a = 1\n        b = 2\n        c = 3\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].line == 3


def test_terminator_metadata_unchanged_by_new_cases():
    """Record only the terminator and its line in the metadata of a finding after a return.

    Returns:
        None. Asserts the exact terminator metadata on the finding.
    """
    src = "def f():\n    return 1\n    x = 2\n"
    findings = UnreachableCodeRule().analyse(_make_unit(src), _ctx())
    assert findings[0].metadata == {"terminator": "return", "terminatorLine": 2}
