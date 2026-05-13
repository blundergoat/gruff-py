import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.naming.test_naming_consistency_rule import TestNamingConsistencyRule
from gruff.source.source_file import SourceFile


def _unit(source: str, display_path: str = "tests/test_x.py") -> AnalysisUnit:
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
    rule = TestNamingConsistencyRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_mixed_snake_and_camel_fires():
    src = "def test_foo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["snakeCaseCount"] == 1
    assert findings[0].metadata["camelCaseCount"] == 1


def test_consistent_snake_does_not_fire():
    src = "def test_foo(): pass\ndef test_bar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_consistent_camel_does_not_fire():
    src = "def testFoo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_methods_in_test_class_count():
    src = "class TestSomething:\n    def test_a(self): pass\n    def testB(self): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_non_test_file_does_not_fire():
    src = "def test_foo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(_unit(src, display_path="src/foo.py"), _ctx())
    assert findings == []


def test_test_dir_path_recognised():
    src = "def test_foo(): pass\ndef testBar(): pass\n"
    findings = TestNamingConsistencyRule().analyse(
        _unit(src, display_path="tests/integration/something.py"), _ctx()
    )
    assert len(findings) == 1


def test_definition():
    d = TestNamingConsistencyRule().definition()
    assert d.id == "naming.test-naming-consistency"
