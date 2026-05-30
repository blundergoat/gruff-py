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


def test_finding_carries_fingerprint_and_remediation():
    findings = FileLengthRule().analyse(_make_unit(150), _ctx(threshold=100))
    finding = findings[0]
    assert len(finding.fingerprint()) == 16
    assert finding.remediation is not None
    assert finding.line == 1
    assert finding.end_line == 150
