import ast

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.abbreviation_rule import AbbreviationRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "x.py") -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit at display_path.

    Args:
        source: Python source to parse.
        display_path: Project-relative path of the unit; defaults to x.py.

    Returns:
        A unit at display_path whose AST nodes carry parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # ast.AST does not declare parent, which the rule uses to find enclosing functions.
    return AnalysisUnit(
        file=SourceFile(absolute_path=f"/{display_path}", display_path=display_path, type="python"),
        source=source,
        tree=tree,
    )


def _ctx(accepted: tuple[str, ...] = ()) -> RuleContext:
    """Build a rule context with the abbreviation rule enabled and the given accepted abbreviations.

    Args:
        accepted: Abbreviations the config accepts; defaults to none.

    Returns:
        A context whose config enables the abbreviation rule and accepts those abbreviations.
    """
    rule = AbbreviationRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={rule.definition().id: RuleSettings(enabled=True)},
            accepted_abbreviations=accepted,
        ),
    )


def test_function_abbreviation_fires():
    """Report one finding for the function load_cfg and identify cfg as the abbreviation.

    Returns:
        None after checking for one finding whose metadata identifies load_cfg as a function and cfg as its abbreviation.
    """
    src = "def load_cfg() -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata == {
        "identifier": "load_cfg",
        "kind": "function",
        "abbreviation": "cfg",
    }


def test_parameter_abbreviation_fires():
    """Report the parameter req once as an abbreviation.

    Returns:
        None after the assertions succeed.
    """
    src = "def handle(req: object) -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "parameter"
    assert findings[0].metadata["abbreviation"] == "req"


def test_standard_variadic_names_are_skipped():
    """Report nothing for the standard variadic parameter names args and kwargs.

    Returns:
        None after the assertion succeeds.
    """
    src = "def build(*args: object, **kwargs: object) -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_local_variable_abbreviation_fires_once_per_identifier():
    """Report a local msg assigned twice once.

    Returns:
        None after the assertions succeed.
    """
    src = "def f() -> None:\n    msg = 'hello'\n    msg = 'again'\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert {finding.metadata["abbreviation"] for finding in findings} == {"msg"}


def test_tuple_assignment_abbreviation_fires():
    """Report req from a tuple assignment once.

    Returns:
        None after the assertions succeed.
    """
    src = "def f() -> None:\n    req, response = pair\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["identifier"] == "req"


def test_accepted_abbreviation_suppresses_finding():
    """Report nothing for abbreviations the config accepts.

    Returns:
        None after the assertion succeeds.
    """
    src = "def load_cfg(ctx: object) -> None:\n    msg = 'hello'\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx(accepted=("cfg", "ctx", "msg")))
    assert findings == []


def test_clear_identifier_does_not_fire():
    """Report nothing for the names load_config, request and message.

    Returns:
        None after checking that load_config, request and message produce no abbreviation findings.
    """
    src = "def load_config(request: object) -> None:\n    message = 'hello'\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_class_names_are_skipped():
    """Report nothing for an abbreviated class name.

    Returns:
        None after the assertion succeeds.
    """
    src = "class Cfg:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_module_level_assignments_are_skipped():
    """Report nothing for an abbreviated module-level assignment.

    Returns:
        None after the assertion succeeds.
    """
    src = "cfg = object()\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_test_files_are_skipped():
    """Report nothing for abbreviations in a test file.

    Returns:
        None after the assertion succeeds.
    """
    src = "def test_uses_cfg(req: object) -> None:\n    msg = 'hello'\n"
    findings = AbbreviationRule().analyse(_unit(src, "tests/test_widget.py"), _ctx())
    assert findings == []


def test_dunder_names_are_skipped():
    """Report nothing for an abbreviation inside a dunder function name.

    Returns:
        None after the assertion succeeds.
    """
    src = "def __ctx__() -> None:\n    pass\n"
    findings = AbbreviationRule().analyse(_unit(src), _ctx())
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
    """Exempt a file under a test or backslash Test directory, but not testing/helpers.py or pkg/test_helpers.py.

    Args:
        display_path: Path of the analysed file; the cases vary its directory and file name.
        exempt: Whether that path should suppress every finding.

    Returns:
        None after the assertion succeeds.
    """
    findings = AbbreviationRule().analyse(_unit("def load_cfg(req):\n    return req\n", display_path), _ctx())
    assert (not findings) is exempt
