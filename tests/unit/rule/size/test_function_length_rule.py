import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.function_length_rule import FunctionLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    # mirror PythonFileParser._attach_parents
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 30, error: int = 60) -> RuleContext:
    rule = FunctionLengthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_under_warning_threshold_emits_no_finding():
    source = "def f():\n    return 1\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=10))
    assert findings == []


_WARNING_BOUNDARY = 5
_BODY_STATEMENT_COUNT = 10
# A def-line + N body statements = N+1 lines in the AST span.
_EXPECTED_REPORTED_LINES = _BODY_STATEMENT_COUNT + 1


def test_above_warning_below_error_emits_warning():
    body = "\n".join(["    x = 1"] * _BODY_STATEMENT_COUNT)
    source = f"def f():\n{body}\n"
    findings = FunctionLengthRule().analyse(
        _make_unit(source), _ctx(warning=_WARNING_BOUNDARY, error=20)
    )
    assert len(findings) == 1
    f = findings[0]
    assert (f.severity, f.symbol) == (Severity.WARNING, "f")
    relevant_metadata = {k: f.metadata[k] for k in ("lines", "threshold", "thresholdType")}
    assert relevant_metadata == {
        "lines": _EXPECTED_REPORTED_LINES,
        "threshold": _WARNING_BOUNDARY,
        "thresholdType": "warning",
    }


def test_above_error_emits_error():
    body = "\n".join(["    x = 1"] * 25)
    source = f"def f():\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.ERROR
    assert f.metadata["lines"] == 26
    assert f.metadata["threshold"] == 20


def test_method_in_class_uses_qualified_symbol():
    body = "\n".join(["        x = 1"] * 8)
    source = f"class C:\n    def m(self):\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    assert findings[0].symbol == "C.m"


def test_nested_functions_emit_independent_findings():
    inner_body = "\n".join(["        x = 1"] * 10)
    outer_body = f"    def inner():\n{inner_body}\n    inner()\n"
    source = f"def outer():\n{outer_body}"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    symbols = {f.symbol for f in findings}
    # outer wraps inner so outer is also long; both should be flagged
    assert "outer" in symbols
    assert "outer.inner" in symbols


def test_decorator_lines_counted():
    source = "@decorator\ndef f():\n    return 1\n"
    # Span = decorator (1) + def (2) + body (3) = 3 lines total
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=2, error=10))
    assert len(findings) == 1
    f = findings[0]
    assert f.metadata["lines"] == 3
    assert f.line == 1  # starts at decorator line


def test_async_function_flagged():
    body = "\n".join(["    x = 1"] * 10)
    source = f"async def f():\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    assert len(findings) == 1
    assert findings[0].symbol == "f"


def test_lambda_is_considered():
    # Lambda + threshold low enough to flag a single-line lambda.
    source = "g = lambda x: x + 1\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=0, error=10))
    assert len(findings) == 1
    assert findings[0].symbol.startswith("<lambda:")
    assert findings[0].metadata["lines"] == 1


def test_definition_uses_default_thresholds():
    definition = FunctionLengthRule().definition()
    assert definition.id == "size.function-length"
    assert definition.default_thresholds == {"warning": 100, "error": 100}


def test_unit_with_no_tree_returns_empty():
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source="", tree=None)
    assert FunctionLengthRule().analyse(unit, _ctx()) == []


def test_findings_carry_fingerprint_and_remediation():
    source = "def f():\n" + "\n".join(["    x = 1"] * 40) + "\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(warning=5, error=20))
    f = findings[0]
    assert len(f.fingerprint()) == 16
    assert f.remediation is not None
    assert f.end_line is not None
