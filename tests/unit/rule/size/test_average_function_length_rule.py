import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.average_function_length_rule import AverageFunctionLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 30, error: int = 60) -> RuleContext:
    rule = AverageFunctionLengthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_class_with_short_methods_emits_no_finding():
    source = "class C:\n    def a(self):\n        return 1\n    def b(self):\n        return 2\n"
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx()) == []


def test_class_with_long_methods_emits_warning():
    body = "\n".join(["        x = 1"] * 8)
    source = (
        f"class C:\n    def a(self):\n{body}\n    def b(self):\n{body}\n    def c(self):\n{body}\n"
    )
    findings = AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.WARNING
    assert f.metadata["methodCount"] == 3
    assert f.metadata["averageLines"] == 9.0  # each method is 9 lines (def + 8 body)


def test_class_above_error_threshold_emits_error():
    body = "\n".join(["        x = 1"] * 25)
    source = (
        f"class C:\n    def a(self):\n{body}\n    def b(self):\n{body}\n    def c(self):\n{body}\n"
    )
    findings = AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR


def test_class_with_one_long_method_emits_nothing():
    body = "\n".join(["        x = 1"] * 25)
    source = f"class C:\n    def a(self):\n{body}\n"
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20)) == []


def test_class_with_no_methods_emits_nothing():
    source = "class C:\n    x = 1\n    y = 2\n"
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20)) == []


def test_nested_class_with_too_few_methods_skipped():
    body = "\n".join(["            x = 1"] * 10)
    source = f"class Outer:\n    class Inner:\n        def m(self):\n{body}\n"
    findings = AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert findings == []


def test_definition_uses_default_thresholds():
    d = AverageFunctionLengthRule().definition()
    assert d.id == "size.average-function-length"
    assert d.default_thresholds == {"warning": 30, "error": 60}
