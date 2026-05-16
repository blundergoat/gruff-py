import shutil
import subprocess

import pytest

from gruffpy.analysis.report import AnalysisReport
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.reporting.json_reporter import JsonReporter
from gruffpy.scoring.score_calculator import ScoreCalculator


def test_json_reporter_matches_php_json_encoding_flags():
    php = shutil.which("php")
    if php is None:
        pytest.skip("php binary not available for JSON byte-equivalence check")

    report = _fixture_report()
    python_json = JsonReporter().render(report)
    php_json = _php_pretty_json(php, python_json)

    assert php_json == python_json


def _fixture_report() -> AnalysisReport:
    finding = Finding(
        rule_id="security.dangerous-function-call",
        message='Dangerous call in path src/example.py with unicode "caf\u00e9".',
        file_path="src/example.py",
        line=12,
        severity=Severity.ERROR,
        pillar=Pillar.SECURITY,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        symbol="module.run",
        remediation="Avoid dynamic execution.",
        metadata={"target": "eval", "path": "src/example.py"},
    )
    findings = (finding,)
    return AnalysisReport(
        tool_version="0.1.0-test",
        requested_paths=("src/example.py",),
        format="json",
        fail_on="none",
        files_discovered=1,
        files_parsed=1,
        ignored_paths=("vendor/package.py",),
        missing_paths=("missing.py",),
        diagnostics=(),
        findings=findings,
        exit_code=0,
        score=ScoreCalculator().calculate(list(findings)),
        filters=FindingDisplayFilter(include_rules=("security.dangerous-function-call",)),
    )


def _php_pretty_json(php: str, json_payload: str) -> str:
    code = (
        "$payload = json_decode(stream_get_contents(STDIN), true, 512, JSON_THROW_ON_ERROR);"
        "echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL;"
    )
    result = subprocess.run(
        [php, "-r", code],
        input=json_payload,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout
