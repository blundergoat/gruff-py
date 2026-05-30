import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.public_method_count_rule import PublicMethodCountRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 15) -> RuleContext:
    rule = PublicMethodCountRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_class_with_few_public_methods_emits_no_finding():
    source = "class C:\n    def m(self):\n        return 1\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []


def test_class_with_many_public_methods_emits_error():
    methods = "\n".join([f"    def m{i}(self):\n        return {i}" for i in range(20)])
    source = f"class C:\n{methods}\n"
    findings = PublicMethodCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.ERROR
    assert f.metadata["publicMethods"] == 20


def test_private_methods_excluded():
    methods = "\n".join([f"    def _m{i}(self):\n        return {i}" for i in range(20)])
    source = f"class C:\n{methods}\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []


def test_dunder_methods_excluded():
    methods = "\n".join([f"    def __m{i}__(self):\n        return {i}" for i in range(20)])
    source = f"class C:\n{methods}\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []


def test_above_error_threshold_emits_error():
    methods = "\n".join([f"    def m{i}(self):\n        return {i}" for i in range(30)])
    source = f"class C:\n{methods}\n"
    findings = PublicMethodCountRule().analyse(_make_unit(source), _ctx())
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["publicMethods"] == 30


def test_unittest_testcase_subclass_is_exempt():
    # TestCase subclasses have one method per test case by design.
    methods = "\n".join([f"    def test_a{i}(self):\n        pass" for i in range(20)])
    source = f"import unittest\nclass MyTest(unittest.TestCase):\n{methods}\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []


def test_pytest_test_prefix_class_is_exempt():
    methods = "\n".join([f"    def test_a{i}(self):\n        pass" for i in range(20)])
    source = f"class TestFoo:\n{methods}\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []


def test_pydantic_basemodel_subclass_is_exempt():
    body = "\n".join(f"    def m{i}(self):\n        return {i}" for i in range(20))
    source = f"from pydantic import BaseModel\nclass S(BaseModel):\n{body}\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []
