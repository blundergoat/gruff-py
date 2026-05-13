import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.size.public_method_count_rule import PublicMethodCountRule
from gruff.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 15, error: int = 25) -> RuleContext:
    rule = PublicMethodCountRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_class_with_few_public_methods_emits_no_finding():
    source = "class C:\n    def m(self):\n        return 1\n"
    assert PublicMethodCountRule().analyse(_make_unit(source), _ctx()) == []


def test_class_with_many_public_methods_emits_warning():
    methods = "\n".join([f"    def m{i}(self):\n        return {i}" for i in range(20)])
    source = f"class C:\n{methods}\n"
    findings = PublicMethodCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.WARNING
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


def test_definition_uses_default_thresholds():
    d = PublicMethodCountRule().definition()
    assert d.id == "size.public-method-count"
    assert d.default_thresholds == {"warning": 15, "error": 25}
