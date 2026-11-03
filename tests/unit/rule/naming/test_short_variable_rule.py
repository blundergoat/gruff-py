import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.short_variable_rule import ShortVariableRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit at display_path.

    Args:
        source: Python source to parse.
        display_path: Project-relative path of the unit; defaults to ``x.py``.

    Returns:
        A unit at display_path whose AST nodes carry parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )


def _ctx(options: dict | None = None) -> RuleContext:
    """Build a rule context with the short variable rule enabled.

    Args:
        options: Rule options; None applies none.

    Returns:
        A context whose config enables the short variable rule with those options.
    """
    rule = ShortVariableRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True, options=options or {})}),
    )


def test_q_variable_fires():
    """Report one finding for source whose only statement assigns ``q``."""
    src = "q = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_short_variable_in_test_file_is_skipped():
    """Report nothing for a one-letter variable in a test file."""
    src = "def test_example():\n    d = {}\n    assert d == {}\n"
    findings = ShortVariableRule().analyse(_unit(src, display_path="tests/test_example.py"), _ctx())
    assert findings == []


def test_i_does_not_fire():
    """Report nothing for ``i``."""
    src = "i = 0\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_x_does_not_fire():
    """Report nothing for ``x``."""
    src = "x = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_underscore_does_not_fire():
    """Report nothing for ``_``."""
    src = "_ = compute()\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_two_char_does_not_fire():
    """Report nothing for the two-letter name ``qq``."""
    src = "qq = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_tuple_assignment_each_checked():
    """Report each of ``a``, ``b`` and ``q`` from one tuple assignment."""
    src = "a, b, q = 1, 2, 3\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    # a, b, q -> a NOT in default accepted, b NOT in accepted, q NOT in accepted
    # default accepted: i,j,k,n,m,x,y,z,e,_,f
    names = {f.metadata["identifier"] for f in findings}
    assert names == {"a", "b", "q"}


def test_configurable_accepted_list():
    """Report only ``r`` when the ``acceptedShortNames`` option accepts ``q``."""
    src = "q = 1\nr = 2\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx(options={"acceptedShortNames": ["q"]}))
    names = {f.metadata["identifier"] for f in findings}
    assert names == {"r"}


def test_ann_assign_fires():
    """Report one finding for source whose only statement is an annotated assignment to ``q``."""
    src = "q: int = 1\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_function_param_does_not_fire():
    """Report nothing for a one-letter parameter."""
    # Parameters are out of scope for this rule.
    src = "def f(q): return q\n"
    findings = ShortVariableRule().analyse(_unit(src), _ctx())
    assert findings == []


@pytest.mark.parametrize(
    "display_path, exempt",
    [
        ("test/helpers.py", True),
        ("pkg/test/helpers.py", True),
        ("pkg\\Test\\helpers.py", True),
        ("testing/helpers.py", False),
        ("pkg/test_helpers.py", False),
    ],
    ids=["root-test-dir", "nested-test-dir", "windows-mixed-case-test-dir", "testing-dir", "test-prefixed-file"],
)
def test_exact_singular_test_directory(display_path: str, exempt: bool) -> None:
    """Exempt a file under a ``test`` or backslash ``Test`` directory, but not ``testing/helpers.py`` or ``pkg/test_helpers.py``.

    Args:
        display_path: Path of the analysed file; the cases vary its directory and file name.
        exempt: Whether that path should suppress every finding.
    """
    findings = ShortVariableRule().analyse(_unit("q = 1\n", display_path), _ctx())
    assert (not findings) is exempt
