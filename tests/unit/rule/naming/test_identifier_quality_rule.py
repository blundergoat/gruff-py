import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.naming.identifier_quality_rule import IdentifierQualityRule
from gruff.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(absolute_path="/x.py", display_path="x.py", type="python"),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    rule = IdentifierQualityRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def test_temp_variable_fires():
    src = "temp = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert "placeholder token 'temp'" in findings[0].metadata["pattern"]


def test_foo_variable_fires():
    src = "foo = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_result1_fires():
    src = "result1 = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1
    assert "numbered placeholder" in findings[0].metadata["pattern"]


def test_data42_fires():
    src = "data42 = []\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert len(findings) == 1


def test_descriptive_name_does_not_fire():
    src = "user_count = 1\nresponse = None\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_temperature_does_not_fire():
    # 'temperature' tokenizes to ['temperature'] — first token 'temperature'
    # is NOT 'temp'. Make sure we match exact tokens, not prefixes.
    src = "temperature = 20\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_dunder_does_not_fire():
    src = "class C:\n    __foo__ = None\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert findings == []


def test_function_name_fires():
    src = "def foo(): return 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert any(f.metadata["identifier"] == "foo" for f in findings)


def test_camel_case_placeholder_fires():
    src = "FooBar = 1\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    # tokens = ['Foo', 'Bar'] -> first 'foo' lower-cased -> placeholder
    assert len(findings) == 1


def test_parameter_temp_fires():
    src = "def f(temp): return temp\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    assert any(f.metadata["identifier"] == "temp" for f in findings)


def test_result_without_number_does_not_fire():
    src = "result = compute()\n"
    findings = IdentifierQualityRule().analyse(_unit(src), _ctx())
    # 'result' alone is fine; only 'result1' / 'result2' fire.
    assert findings == []


def test_definition():
    d = IdentifierQualityRule().definition()
    assert d.id == "naming.identifier-quality"
