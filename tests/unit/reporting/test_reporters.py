import json

from gruff.analysis.report import AnalysisReport
from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.reporting.finding_display_filter import FindingDisplayFilter
from gruff.reporting.github_annotations_reporter import GithubAnnotationsReporter
from gruff.reporting.hotspot_reporter import HotspotReporter
from gruff.reporting.html_reporter import HtmlReporter
from gruff.reporting.json_reporter import JsonReporter
from gruff.reporting.markdown_reporter import MarkdownReporter
from gruff.reporting.sarif_reporter import SarifReporter
from gruff.scoring.score_calculator import ScoreCalculator


def _finding(
    *,
    rule_id: str = "security.dangerous-function-call",
    message: str = "Dangerous call to eval().",
    file_path: str = "src/app.py",
    line: int = 12,
    severity: Severity = Severity.ERROR,
    pillar: Pillar = Pillar.SECURITY,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=message,
        file_path=file_path,
        line=line,
        severity=severity,
        pillar=pillar,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        metadata={"target": "eval"},
    )


def _report(
    findings: tuple[Finding, ...] | None = None,
    filters: FindingDisplayFilter | None = None,
) -> AnalysisReport:
    selected = findings or (_finding(),)
    return AnalysisReport(
        tool_version="0.1.0-test",
        requested_paths=("src",),
        format="json",
        fail_on="none",
        files_discovered=1,
        files_parsed=1,
        ignored_paths=(),
        missing_paths=(),
        diagnostics=(),
        findings=selected,
        exit_code=0,
        score=ScoreCalculator().calculate(list(selected)),
        filters=filters,
    )


def test_json_reporter_records_display_filters():
    report = _report(
        filters=FindingDisplayFilter(
            min_severity=Severity.WARNING,
            include_rules=("security.dangerous-function-call",),
        )
    )

    payload = json.loads(JsonReporter().render(report))

    assert payload["run"]["filters"]["active"] is True
    assert payload["run"]["filters"]["minSeverity"] == "warning"
    assert payload["run"]["filters"]["includeRules"] == ["security.dangerous-function-call"]


def test_markdown_reporter_groups_findings_and_escapes_table_pipes():
    finding = _finding(message="Do not render | as a table break", file_path="src/a|b.py")

    markdown = MarkdownReporter().render(_report((finding,)))

    assert "# gruff-py report" in markdown
    assert "src/a\\|b.py" in markdown
    assert "Do not render \\| as a table break" in markdown


def test_github_annotations_escape_properties_and_data():
    finding = _finding(
        message="bad % value\nnext",
        file_path="src/a:b,thing.py",
    )

    output = GithubAnnotationsReporter().render(_report((finding,)))

    assert output.startswith("::error ")
    assert "file=src/a%3Ab%2Cthing.py" in output
    assert "bad %25 value%0Anext" in output


def test_hotspot_reporter_uses_hotspot_schema():
    payload = json.loads(HotspotReporter().render(_report()))

    assert payload["schemaVersion"] == "gruff.hotspot.v1"
    assert payload["type"] == "hotspot-map"
    assert payload["hotspots"][0]["file"] == "src/app.py"


def test_sarif_reporter_emits_rule_metadata_and_fingerprint():
    payload = json.loads(SarifReporter().render(_report()))
    result = payload["runs"][0]["results"][0]

    assert payload["version"] == "2.1.0"
    assert result["ruleId"] == "security.dangerous-function-call"
    assert result["partialFingerprints"]["gruffFingerprint"]
    assert payload["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["pillar"] == "security"


def test_html_reporter_escapes_untrusted_values_and_interactive_controls():
    finding = _finding(
        message='<img src=x onerror=alert(1)> "quote"',
        file_path='src/"evil".py',
    )

    html = HtmlReporter("/workspace/project", interactive=True).render(_report((finding,)))

    assert "<img src=x onerror=alert(1)>" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "src/&quot;evil&quot;.py" in html
    assert 'class="finding-filters"' in html
    assert "data-findings-list" in html


def test_display_filter_applies_minimum_severity_and_rule_filters():
    findings = (
        _finding(severity=Severity.ERROR),
        _finding(
            rule_id="docs.missing-readme",
            severity=Severity.ADVISORY,
            pillar=Pillar.DOCUMENTATION,
        ),
    )
    display_filter = FindingDisplayFilter(
        min_severity=Severity.WARNING,
        exclude_rules=("security.dangerous-function-call",),
    )

    assert display_filter.apply(findings) == []
    assert display_filter.to_dict() == {
        "active": True,
        "minSeverity": "warning",
        "includePillars": [],
        "excludePillars": [],
        "includeRules": [],
        "excludeRules": ["security.dangerous-function-call"],
    }
