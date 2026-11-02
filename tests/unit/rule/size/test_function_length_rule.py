import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.function_length_rule import FunctionLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``x.py``.

    Args:
        source: Python source to parse.

    Returns:
        A unit for ``x.py`` whose AST nodes carry parent links.
    """
    tree = ast.parse(source)
    # mirror PythonFileParser._attach_parents
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 30) -> RuleContext:
    """Build a rule context with the function length rule enabled at an error threshold.

    Args:
        threshold: Value the rule allows before it reports; defaults to 30.

    Returns:
        A context whose config enables only the function length rule at that threshold.
    """
    rule = FunctionLengthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_under_warning_threshold_emits_no_finding():
    """Report nothing for a two-line function against a threshold of 5."""
    source = "def f():\n    return 1\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert findings == []


_WARNING_BOUNDARY = 5
_BODY_STATEMENT_COUNT = 10
# A def-line + N body statements = N+1 lines in the AST span.
_EXPECTED_REPORTED_LINES = _BODY_STATEMENT_COUNT + 1


def test_above_threshold_emits_error():
    """Report an 11-line function against a threshold of 5 as one error finding on ``f`` whose metadata holds the lines, threshold and type."""
    body = "\n".join(["    x = 1"] * _BODY_STATEMENT_COUNT)
    source = f"def f():\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=_WARNING_BOUNDARY))
    assert len(findings) == 1
    f = findings[0]
    assert (f.severity, f.symbol) == (Severity.ERROR, "f")
    relevant_metadata = {k: f.metadata[k] for k in ("lines", "threshold", "thresholdType")}
    assert relevant_metadata == {
        "lines": _EXPECTED_REPORTED_LINES,
        "threshold": _WARNING_BOUNDARY,
        "thresholdType": "error",
    }


def test_far_above_threshold_emits_error():
    """Report a 31-line function against a threshold of 20 as one error finding in the upper limit band."""
    # 31 lines against 20 is at one and a half times the limit or more, so the finding keeps error severity.
    body = "\n".join(["    x = 1"] * 30)
    source = f"def f():\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=20))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.ERROR
    assert f.metadata["limitBand"] == "upper"
    assert f.metadata["lines"] == 31
    assert f.metadata["threshold"] == 20


def test_method_in_class_uses_qualified_symbol():
    """Report a long method once, as ``C.m``."""
    body = "\n".join(["        x = 1"] * 8)
    source = f"class C:\n    def m(self):\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    assert findings[0].symbol == "C.m"


def test_nested_functions_emit_independent_findings():
    """Report both ``outer`` and ``outer.inner`` when a long nested function makes both long."""
    inner_body = "\n".join(["        x = 1"] * 10)
    outer_body = f"    def inner():\n{inner_body}\n    inner()\n"
    source = f"def outer():\n{outer_body}"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    symbols = {f.symbol for f in findings}
    # outer wraps inner so outer is also long; both should be flagged
    assert "outer" in symbols
    assert "outer.inner" in symbols


def test_decorator_lines_are_free_but_still_mark_the_start():
    """Measure a decorated function at 2 lines, excluding its decorator, while the finding starts at the decorator line."""
    source = "@decorator\ndef f():\n    return 1\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=1))
    assert len(findings) == 1
    f = findings[0]
    assert f.metadata["lines"] == 2
    assert f.line == 1  # the finding still starts at the decorator line


def test_function_with_101_code_lines_is_reported_whatever_its_documentation():
    """Report a documented function with 101 code lines once against a threshold of 100, measuring 101."""
    docstring = '    """Builds the values.\n\n    Every assignment below is code.\n    """'
    body = "\n".join(f"    x{i} = {i}" for i in range(100))
    source = f"def f():\n{docstring}\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=100))
    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 101


def test_documented_short_function_is_not_reported():
    """Report nothing for a one-statement function with a fifty-line docstring and 150 comment lines."""
    explanation = "\n".join(f"    Line {i} of a long explanation." for i in range(50))
    docstring = f'    """Returns one.\n\n{explanation}\n    """'
    comments = "\n".join(f"    # Step {i} of the reasoning." for i in range(150))
    source = f"def f():\n{docstring}\n{comments}\n    return 1\n"
    assert FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=100)) == []


def test_async_function_flagged():
    """Report a long async function once, as ``f``."""
    body = "\n".join(["    x = 1"] * 10)
    source = f"async def f():\n{body}\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    assert findings[0].symbol == "f"


def test_lambda_is_considered():
    """Report a one-line lambda once against a threshold of 0, with a symbol starting ``<lambda:`` and a count of 1."""
    # Lambda + threshold low enough to flag a single-line lambda.
    source = "g = lambda x: x + 1\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=0))
    assert len(findings) == 1
    assert findings[0].symbol.startswith("<lambda:")
    assert findings[0].metadata["lines"] == 1


def test_unit_with_no_tree_returns_empty():
    """Report nothing for a unit without a parsed tree."""
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source="", tree=None)
    assert FunctionLengthRule().analyse(unit, _ctx()) == []


def test_findings_carry_fingerprint_and_remediation():
    """Give the first finding a 16-character fingerprint, a remediation and an end line."""
    source = "def f():\n" + "\n".join(["    x = 1"] * 40) + "\n"
    findings = FunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    f = findings[0]
    assert len(f.fingerprint()) == 16
    assert f.remediation is not None
    assert f.end_line is not None
