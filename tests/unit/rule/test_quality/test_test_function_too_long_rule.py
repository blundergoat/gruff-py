from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.rule.context import RuleContext
from gruffpy.rule.test_quality.test_function_too_long_rule import TestFunctionTooLongRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def _ctx(threshold: int = 100) -> RuleContext:
    rule = TestFunctionTooLongRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_short_test_skipped():
    src = "def test_foo():\n    assert 1 + 1 == 2\n"
    assert TestFunctionTooLongRule().analyse(make_unit(src), default_ctx()) == []


def test_under_default_threshold_emits_no_finding():
    body = "\n".join(f"    x{i} = {i}" for i in range(60))
    src = f"def test_foo():\n{body}\n    assert True\n"
    assert TestFunctionTooLongRule().analyse(make_unit(src), default_ctx()) == []


def test_above_default_threshold_fires_at_error_severity():
    body = "\n".join(f"    x{i} = {i}" for i in range(120))
    src = f"def test_foo():\n{body}\n    assert True\n"
    findings = TestFunctionTooLongRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["lines"] > 100
    assert finding.metadata["threshold"] == 100
    assert finding.metadata["thresholdType"] == "error"


def test_custom_threshold_above_emits_error():
    body = "\n".join(f"    x{i} = {i}" for i in range(75))
    src = f"def test_foo():\n{body}\n    assert True\n"
    findings = TestFunctionTooLongRule().analyse(make_unit(src), _ctx(threshold=50))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["thresholdType"] == "error"
