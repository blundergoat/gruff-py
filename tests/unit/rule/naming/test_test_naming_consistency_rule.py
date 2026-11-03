import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.naming.test_naming_consistency_rule import TestNamingConsistencyRule
from gruffpy.source.source_file import SourceFile


def _unit(source: str, display_path: str = "tests/test_x.py") -> AnalysisUnit:
    """Parse source into an analysis unit at display_path.

    Args:
        source: Python source to parse.
        display_path: Project-relative path of the unit; defaults to a test file under ``tests``.

    Returns:
        A unit holding the parsed tree, without parent links, at display_path.
    """
    tree = ast.parse(source)
    return AnalysisUnit(
        file=SourceFile(
            absolute_path=f"/{display_path}",
            display_path=display_path,
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    """Build a rule context with the test naming consistency rule enabled.

    Returns:
        A context whose config enables only the test naming consistency rule.
    """
    rule = TestNamingConsistencyRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_mixed_snake_and_camel_fires():
    """Report a test file mixing one snake-case and one camel-case test name once, with both counts."""
    src = "def test_foo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["snakeCaseCount"] == 1
    assert findings[0].metadata["camelCaseCount"] == 1


def test_consistent_snake_does_not_fire():
    """Report nothing when every test name is snake case."""
    src = "def test_foo(): pass\ndef test_bar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_consistent_camel_does_not_fire():
    """Report nothing when every test name is camel case."""
    src = "def testFoo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_methods_in_test_class_count():
    """Report mixed snake-case and camel-case test methods in a test class once."""
    src = "class TestSomething:\n    def test_a(self): pass\n    def testB(self): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_non_test_file_does_not_fire():
    """Report nothing for mixed test names in a file outside the tests."""
    src = "def test_foo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src, display_path="src/foo.py"), _ctx())
    assert findings == []


def test_test_dir_path_recognised():
    """Report mixed test names once in a file under ``tests`` whose name lacks the ``test_`` prefix."""
    src = "def test_foo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src, display_path="tests/integration/something.py"), _ctx())
    assert len(findings) == 1
