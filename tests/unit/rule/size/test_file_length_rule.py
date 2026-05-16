import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
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


def _ctx(warning: int = 400, error: int = 800) -> RuleContext:
    rule = FileLengthRule()
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
    findings = FileLengthRule().analyse(_make_unit(50), _ctx(warning=100, error=200))
    assert findings == []


def test_above_warning_below_error_emits_warning():
    findings = FileLengthRule().analyse(_make_unit(150), _ctx(warning=100, error=200))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.WARNING
    assert finding.rule_id == "size.file-length"
    assert finding.metadata["lines"] == 150
    assert finding.metadata["threshold"] == 100
    assert finding.metadata["thresholdType"] == "warning"


def test_above_error_emits_error():
    findings = FileLengthRule().analyse(_make_unit(300), _ctx(warning=100, error=200))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["lines"] == 300
    assert finding.metadata["threshold"] == 200
    assert finding.metadata["thresholdType"] == "error"


def test_finding_carries_fingerprint_and_remediation():
    findings = FileLengthRule().analyse(_make_unit(150), _ctx(warning=100, error=200))
    finding = findings[0]
    assert len(finding.fingerprint()) == 16
    assert finding.remediation is not None
    assert finding.line == 1
    assert finding.end_line == 150


def test_definition_uses_default_thresholds():
    definition = FileLengthRule().definition()
    assert definition.id == "size.file-length"
    assert definition.default_thresholds == {"warning": 400, "error": 800}
    assert definition.default_severity == Severity.WARNING
