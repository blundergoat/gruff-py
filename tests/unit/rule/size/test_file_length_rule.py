import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.file_length_rule import FileLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(line_count: int) -> AnalysisUnit:
    if line_count == 0:
        source = ""
        tree: ast.AST | None = None
    else:
        source = "\n".join(["x = 1"] * line_count)
        tree = ast.parse(source)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 400) -> RuleContext:
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
    findings = FileLengthRule().analyse(_make_unit(50), _ctx(threshold=100))
    assert findings == []


_WARNING_BOUNDARY = 100
_FILE_LINES_OVER_WARNING = 150


def test_above_threshold_emits_error():
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
    findings = FileLengthRule().analyse(_make_unit(300), _ctx(threshold=200))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["lines"] == 300
    assert finding.metadata["threshold"] == 200
    assert finding.metadata["thresholdType"] == "error"


def test_comment_and_blank_padding_is_free():
    source = "\n".join(["x = 1"] * 90 + ["# note"] * 30 + [""] * 20)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    assert FileLengthRule().analyse(unit, _ctx(threshold=100)) == []


def test_substantive_lines_over_threshold_still_fire():
    source = "\n".join(["x = 1"] * 101 + ["# note"] * 30)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    findings = FileLengthRule().analyse(unit, _ctx(threshold=100))
    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 101
    assert findings[0].end_line == 131


def test_docstring_lines_are_free_but_data_strings_count():
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


def test_one_line_definition_docstring_keeps_its_header_counted():
    # A docstring sharing the def line must not free that line of code.
    source = "\n".join(['def tiny(): """doc"""'] * 101)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    unit = AnalysisUnit(file=file, source=source, tree=ast.parse(source))
    findings = FileLengthRule().analyse(unit, _ctx(threshold=100))
    assert len(findings) == 1
    assert findings[0].metadata["lines"] == 101


def test_finding_carries_fingerprint_and_remediation():
    findings = FileLengthRule().analyse(_make_unit(150), _ctx(threshold=100))
    finding = findings[0]
    assert len(finding.fingerprint()) == 16
    assert finding.remediation is not None
    assert finding.line == 1
    assert finding.end_line == 150
