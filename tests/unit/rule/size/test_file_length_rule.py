import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.file_length_rule import FileLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(line_count: int) -> AnalysisUnit:
    """Build an analysis unit for ``x.py`` holding line_count assignment lines, or an empty unit without a tree for 0.

    Args:
        line_count: Number of ``x = 1`` lines; 0 gives empty source and no tree.

    Returns:
        A unit with that many assignment lines and a parsed tree, or empty source and no tree.
    """
    if line_count == 0:
        source = ""
        tree: ast.AST | None = None
    else:
        source = "\n".join(["x = 1"] * line_count)
        tree = ast.parse(source)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 400) -> RuleContext:
    """Build a rule context with the file length rule enabled at an error threshold.

    Args:
        threshold: Value the rule allows before it reports; defaults to 400.

    Returns:
        A context whose config enables only the file length rule at that threshold.
    """
    rule = FileLengthRule()
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
    """Report nothing for 50 lines against a threshold of 100."""
    findings = FileLengthRule().analyse(_make_unit(50), _ctx(threshold=100))
    assert findings == []


_WARNING_BOUNDARY = 100
_FILE_LINES_OVER_WARNING = 150


def test_above_threshold_emits_error():
    """Report 150 lines against a threshold of 100 as one error finding whose metadata holds the lines, threshold and threshold type."""
    findings = FileLengthRule().analyse(
        _make_unit(_FILE_LINES_OVER_WARNING),
        _ctx(threshold=_WARNING_BOUNDARY),
    )
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.severity, finding.rule_id) == (Severity.ERROR, "size.file-length")
    relevant_metadata = {k: finding.metadata[k] for k in ("lines", "threshold", "thresholdType")}
    assert relevant_metadata == {
        "lines": _FILE_LINES_OVER_WARNING,
        "threshold": _WARNING_BOUNDARY,
        "thresholdType": "error",
    }


def test_far_above_threshold_emits_error():
    """Report 300 lines against a threshold of 200 as one error finding carrying those numbers."""
    findings = FileLengthRule().analyse(_make_unit(300), _ctx(threshold=200))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["lines"] == 300
    assert finding.metadata["threshold"] == 200
    assert finding.metadata["thresholdType"] == "error"


def test_comment_and_blank_padding_is_free():
    """Report nothing for 90 code lines padded past a threshold of 100 with comments and blanks."""
    source = "\n".join(["x = 1"] * 90 + ["# note"] * 30 + [""] * 20)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    assert FileLengthRule().analyse(unit, _ctx(threshold=100)) == []


def test_substantive_lines_over_threshold_still_fire():
    """Report 101 code lines once, with the finding ending at line 131 after thirty trailing comments."""
    source = "\n".join(["x = 1"] * 101 + ["# note"] * 30)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    findings = FileLengthRule().analyse(unit, _ctx(threshold=100))
    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 101
    assert findings[0].end_line == 131


def test_docstring_lines_are_free_but_data_strings_count():
    """Report nothing for 90 code lines after a 62-line module docstring, but one finding when those lines are a data string instead."""
    # PEP 257 docstrings are documentation and free; the same literal as data still counts.
    docstring_body = "\n".join(["'''Module docs.", *(["docs line"] * 60), "'''"])
    source = docstring_body + "\n" + "\n".join(["x = 1"] * 90)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    assert FileLengthRule().analyse(unit, _ctx(threshold=100)) == []

    data_lines = ["PAYLOAD = '''start", *(["payload line"] * 60), "'''", *(["x = 1"] * 90)]
    data_source = "\n".join(data_lines)
    data_unit = AnalysisUnit(file=file, source=data_source, tree=ast.parse(data_source))
    findings = FileLengthRule().analyse(data_unit, _ctx(threshold=100))
    assert len(findings) == 1


def test_hash_prefixed_lines_inside_multiline_data_still_count():
    """Count a hash-prefixed line inside a multi-line data string, measuring the file at 4 lines."""
    source = 'PAYLOAD = """start\n# data\npayload\n"""\n'
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))

    findings = FileLengthRule().analyse(unit, _ctx(threshold=3))

    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 4


def test_inline_multiline_docstring_counts_only_code_bearing_header():
    """Report one finding measuring 1 line for a function whose multi-line docstring starts on the ``def`` line."""
    source = 'def tiny(): """Summary.\nContinuation.\n"""\n'
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))

    findings = FileLengthRule().analyse(unit, _ctx(threshold=0))

    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 1


def test_parenthesized_multiline_docstring_is_free():
    """Report one finding measuring 1 line for a function whose one-line docstring is wrapped in parentheses across three lines."""
    source = 'def tiny():\n    (\n        "Summary."\n    )\n'
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))

    findings = FileLengthRule().analyse(unit, _ctx(threshold=0))

    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 1


def test_one_line_definition_docstring_keeps_its_header_counted():
    """Count all 101 ``def`` lines that each carry a one-line docstring."""
    # A docstring sharing the def line must not free that line of code.
    source = "\n".join(['def tiny(): """doc"""'] * 101)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    findings = FileLengthRule().analyse(unit, _ctx(threshold=100))
    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 101


def test_finding_carries_fingerprint_and_remediation():
    """Give the file-length finding a 16-character fingerprint, a remediation and a span from line 1 to 150."""
    findings = FileLengthRule().analyse(_make_unit(150), _ctx(threshold=100))
    finding = findings[0]
    assert len(finding.fingerprint()) == 16
    assert finding.remediation is not None
    assert finding.line == 1
    assert finding.end_line == 150
