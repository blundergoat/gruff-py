import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.class_length_rule import ClassLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 300, error: int = 500) -> RuleContext:
    rule = ClassLengthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_short_class_emits_no_finding():
    source = "class C:\n    x = 1\n"
    assert ClassLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=10)) == []


def test_long_class_emits_warning():
    body = "\n".join(["    x = 1"] * 10)
    source = f"class C:\n{body}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.WARNING
    assert f.symbol == "C"
    assert f.metadata["lines"] == 11


def test_long_class_emits_error_above_error_threshold():
    body = "\n".join(["    x = 1"] * 30)
    source = f"class C:\n{body}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR


def test_nested_class_emits_qualified_symbol():
    inner = "\n".join(["        x = 1"] * 10)
    source = f"class Outer:\n    class Inner:\n{inner}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    symbols = {f.symbol for f in findings}
    assert "Outer" in symbols
    assert "Outer.Inner" in symbols


def test_decorator_counted_in_class_span():
    body = "\n".join(["    x = 1"] * 5)
    source = f"@dataclass\nclass C:\n{body}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    f = findings[0]
    # decorator (1) + class (2) + 5 body lines = 7
    assert f.metadata["lines"] == 7
    assert f.line == 1


def test_definition_uses_default_thresholds():
    d = ClassLengthRule().definition()
    assert d.id == "size.class-length"
    assert d.default_thresholds == {"warning": 300, "error": 500}
