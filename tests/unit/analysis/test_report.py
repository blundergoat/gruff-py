from gruffpy.analysis.report import AnalysisReport
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity


def _finding(
    *,
    rule_id: str,
    severity: Severity = Severity.WARNING,
    confidence: Confidence = Confidence.HIGH,
    line: int = 1,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message="msg",
        file_path="src/x.py",
        line=line,
        severity=severity,
        pillar=Pillar.COMPLEXITY,
        tier=RuleTier.V01,
        confidence=confidence,
    )


def _report(findings: tuple[Finding, ...]) -> AnalysisReport:
    return AnalysisReport(
        tool_version="0.1.2-test",
        requested_paths=("src",),
        format="text",
        fail_on="none",
        files_discovered=1,
        files_parsed=1,
        ignored_paths=(),
        missing_paths=(),
        diagnostics=(),
        findings=findings,
        exit_code=0,
    )


def test_finding_counts_by_rule_returns_empty_list_when_no_findings():
    rows = _report(()).finding_counts_by_rule()

    assert rows == []


def test_finding_counts_by_rule_sorts_by_count_desc_then_rule_id_asc():
    findings = (
        _finding(rule_id="b.rule"),
        _finding(rule_id="a.rule"),
        _finding(rule_id="b.rule"),
        _finding(rule_id="c.rule"),
        _finding(rule_id="a.rule"),
        _finding(rule_id="a.rule"),
    )

    rows = _report(findings).finding_counts_by_rule()

    assert [(row["ruleId"], row["count"]) for row in rows] == [
        ("a.rule", 3),
        ("b.rule", 2),
        ("c.rule", 1),
    ]


def test_finding_counts_by_rule_includes_severity_and_confidence_from_findings():
    findings = (
        _finding(rule_id="naming.x", severity=Severity.ADVISORY, confidence=Confidence.MEDIUM),
        _finding(rule_id="naming.x", severity=Severity.ADVISORY, confidence=Confidence.MEDIUM),
        _finding(rule_id="complexity.y", severity=Severity.WARNING, confidence=Confidence.HIGH),
    )

    rows = _report(findings).finding_counts_by_rule()

    by_id = {row["ruleId"]: row for row in rows}
    assert by_id["naming.x"]["severity"] == "advisory"
    assert by_id["naming.x"]["confidence"] == "medium"
    assert by_id["complexity.y"]["severity"] == "warning"
    assert by_id["complexity.y"]["confidence"] == "high"
