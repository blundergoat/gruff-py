"""Protect every report format from user-visible and serialized contract drift.

The suite feeds one native analysis report through terminal, automation, and
browser renderers so reviewers see consistent findings without schema churn.
"""

import json
from dataclasses import dataclass, replace
from typing import Any

import pytest

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.finding.baseline_identity import finding_identities
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.reporting.github_annotations_reporter import GithubAnnotationsReporter
from gruffpy.reporting.hotspot_reporter import HotspotReporter
from gruffpy.reporting.html_reporter import HtmlReporter
from gruffpy.reporting.json_reporter import JsonReporter
from gruffpy.reporting.markdown_reporter import MarkdownReporter
from gruffpy.reporting.sarif_reporter import SarifReporter
from gruffpy.reporting.text_reporter import TextReporter
from gruffpy.rule.registry import RuleRegistry
from gruffpy.scoring.score_calculator import ScoreCalculator
from tests.unit.rule.security._helpers import default_ctx, make_text_unit


@dataclass(frozen=True, slots=True)
class _FindingSpec:
    """Describe one representative finding shown across reporter journeys.

    Tests override only the user-visible classification or location they need,
    keeping every other finding field stable across format comparisons.
    """

    rule_id: str = "security.dangerous-function-call"
    message: str = "Dangerous call to eval()."
    file_path: str = "src/app.py"
    line: int | None = 12
    severity: Severity = Severity.ERROR
    pillar: Pillar = Pillar.SECURITY
    end_line: int | None = None
    column: int | None = None
    symbol: str | None = None
    remediation: str | None = None
    secondary_pillars: tuple[Pillar, ...] = ()
    metadata: dict[str, object] | None = None


def _finding(**overrides: Any) -> Finding:
    """Build one reporter finding with concise defaults and selected overrides.

    Args:
        overrides: Optional field replacements; empty input keeps the default finding.

    Returns:
        Complete finding for reporter input; never None.
    """
    spec = replace(_FindingSpec(), **overrides)
    return Finding(
        rule_id=spec.rule_id,
        message=spec.message,
        file_path=spec.file_path,
        line=spec.line,
        severity=spec.severity,
        pillar=spec.pillar,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        end_line=spec.end_line,
        column=spec.column,
        symbol=spec.symbol,
        remediation=spec.remediation,
        secondary_pillars=spec.secondary_pillars,
        metadata=spec.metadata if spec.metadata is not None else {"target": "eval"},
    )


def _report(
    findings: tuple[Finding, ...] | None = None,
    filters: FindingDisplayFilter | None = None,
    diagnostics: tuple[RunDiagnostic, ...] = (),
) -> AnalysisReport:
    """Build the native report a user would send to each output renderer.

    Args:
        findings: Findings to render; None or empty uses one representative default.
        filters: Optional display filter; None means the user requested no filtering.

    Returns:
        Scored analysis report ready for rendering; never None.
    """
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
        diagnostics=diagnostics,
        findings=selected,
        exit_code=0,
        score=ScoreCalculator().calculate(list(selected), 10),
        filters=filters,
    )


_ANALYSIS_RENDERERS = {
    "github": GithubAnnotationsReporter,
    "hotspot": HotspotReporter,
    "html": HtmlReporter,
    "json": JsonReporter,
    "markdown": MarkdownReporter,
    "sarif": SarifReporter,
    "text": TextReporter,
}


def _bounded_deep_scan_report() -> AnalysisReport:
    """Build a report whose only diagnostic is a nonfatal bounded deep scan.

    Returns:
        A report carrying one bounded-deep-scan diagnostic for ``src/large.py``.
    """
    diagnostic = RunDiagnostic(
        type="bounded-deep-scan",
        message=("path=src/large.py; lines=20001; bytes=2000001; maxLines=20000; maxBytes=2000000; override=config"),
        file_path="src/large.py",
        line=1,
        invalidates_run=False,
    )
    return _report(diagnostics=(diagnostic,))


@pytest.mark.parametrize("renderer_name", sorted(_ANALYSIS_RENDERERS), ids=sorted(_ANALYSIS_RENDERERS))
def test_bounded_deep_scan_is_visible_in_every_analysis_renderer(renderer_name: str) -> None:
    """No surface may degrade a file silently, so every renderer states the budget note.

    Args:
        renderer_name: Key of the renderer under test in ``_ANALYSIS_RENDERERS``.
    """
    output = _ANALYSIS_RENDERERS[renderer_name]().render(_bounded_deep_scan_report())

    assert "bounded-deep-scan" in output.casefold()
    assert "override=config" in output


def test_bounded_deep_scan_annotates_github_and_notes_sarif() -> None:
    """The two machine surfaces carry the note in their own shape rather than as prose."""
    report = _bounded_deep_scan_report()

    assert "::notice file=src/large.py,title=bounded-deep-scan,line=1::" in GithubAnnotationsReporter().render(report)
    invocation = json.loads(SarifReporter().render(report))["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is True
    assert invocation["toolExecutionNotifications"][0]["level"] == "note"


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


_PARTIAL_PROJECT_CONTEXT_CAVEAT = "partial project scan: project-wide rules may need full-project context"


def _report_with_partial_context(
    scoring_mode: str = "full-project",
    caveat: str = _PARTIAL_PROJECT_CONTEXT_CAVEAT,
) -> AnalysisReport:
    """Build a report carrying the scan caveat and selected scoring mode.

    Args:
        scoring_mode: Existing full-project/diff value shown by score consumers.
        caveat: Non-empty run context shown only by human-readable reporters.

    Returns:
        Native report with unchanged findings, score values, and exit code.
    """
    base_report = _report()
    return replace(
        base_report,
        score=replace(base_report.score, scope=scoring_mode),
        partial_context_caveat=caveat,
    )


def test_native_json_scopes_partial_context_under_python_run_extensions() -> None:
    """Keep port-specific caveats outside the shared run field namespace."""
    native_payload = json.loads(JsonReporter().render(_report_with_partial_context()))

    assert native_payload["run"] == {
        "failOn": "none",
        "format": "json",
        "inputs": ["src"],
        "projectRoot": ".",
        "extensions": {"py": {"run": {"partialContextCaveat": _PARTIAL_PROJECT_CONTEXT_CAVEAT}}},
    }
    assert native_payload["score"]["scope"] == "full-project"
    assert "scanScope" not in json.dumps(native_payload)


def test_hotspot_keeps_existing_scope_shape_for_partial_context() -> None:
    """Keep hotspot scoring-mode keys frozen while human labels become clearer."""
    hotspot_payload = json.loads(HotspotReporter().render(_report_with_partial_context()))

    assert set(hotspot_payload) == {
        "schemaVersion",
        "type",
        "limitations",
        "scope",
        "diagnostics",
        "hotspots",
    }
    assert hotspot_payload["scope"] == "full-project"
    assert "scanScope" not in hotspot_payload


def test_text_reporter_keeps_family_contract_block_byte_for_value() -> None:
    """Keep the ratified masthead, score summary, and finding block unchanged."""
    rendered_text = TextReporter().render(_report())

    assert rendered_text.startswith("gruff-py 0.1.0-test analyse\n")
    # FAMILY-CONTRACT section 1 freezes the line shape, not the number. The one high-confidence
    # error weighs 12 over ten evaluated files, so the ratified curve scores security 53.85 and the
    # other 11 scored pillars stay at 100: (1153.85 / 12).
    assert ("Composite: A (96.15 / 100)\nFindings: 1 total · 1 error · 0 warning · 0 advisory\n") in rendered_text
    # FAMILY-CONTRACT section 1 made the rs/ts dash-line the family canon at this break, so the
    # three-line block gruff-py used to emit is now one line per finding.
    assert ("- [error] src/app.py:12 security.dangerous-function-call - Dangerous call to eval().\n") in rendered_text


@pytest.mark.parametrize("scoring_mode", ("full-project", "diff"), ids=("full", "diff"))
def test_text_reporter_distinguishes_scan_context_from_scoring_mode(
    scoring_mode: str,
) -> None:
    """Give terminal users separate scan-context and scoring-mode labels.

    Args:
        scoring_mode: Existing score mode shown as full-project or diff.
    """
    rendered_text = TextReporter().render(_report_with_partial_context(scoring_mode))
    detailed_finding_position = rendered_text.index("security.dangerous-function-call - Dangerous call to eval().")
    scoring_mode_position = rendered_text.index(f"  Scoring mode: {scoring_mode}")
    scan_context_position = rendered_text.index("Scan context")

    assert f"Scan context\n  Caveat: {_PARTIAL_PROJECT_CONTEXT_CAVEAT}" in rendered_text
    assert f"  Scoring mode: {scoring_mode}" in rendered_text
    assert detailed_finding_position < scoring_mode_position < scan_context_position
    assert "  Scope:" not in rendered_text


@pytest.mark.parametrize("scoring_mode", ("full-project", "diff"), ids=("full", "diff"))
def test_markdown_reporter_distinguishes_scan_context_from_scoring_mode(
    scoring_mode: str,
) -> None:
    """Give pull-request users separate scan-context and scoring-mode labels.

    Args:
        scoring_mode: Existing score mode shown as full-project or diff.
    """
    rendered_markdown = MarkdownReporter().render(_report_with_partial_context(scoring_mode))

    assert f"**Scan context:** {_PARTIAL_PROJECT_CONTEXT_CAVEAT}" in rendered_markdown
    assert f"**Scoring mode:** {scoring_mode}" in rendered_markdown
    assert "**Scope:**" not in rendered_markdown


@pytest.mark.parametrize("scoring_mode", ("full-project", "diff"), ids=("full", "diff"))
def test_html_reporter_distinguishes_scan_context_from_scoring_mode(
    scoring_mode: str,
) -> None:
    """Give browser users separate escaped scan-context and score-mode labels.

    Args:
        scoring_mode: Existing score mode shown as full-project or diff.
    """
    rendered_html = HtmlReporter().render(_report_with_partial_context(scoring_mode))

    assert '<section class="chart-section scan-context">' in rendered_html
    assert "scan context" in rendered_html
    assert '<span class="label">scoring mode</span>' in rendered_html
    assert f'<span class="val">{scoring_mode}</span>' in rendered_html
    assert _PARTIAL_PROJECT_CONTEXT_CAVEAT in rendered_html


def test_human_reporters_do_not_invent_full_scan_context_without_caveat() -> None:
    """Omit scan-context claims when the runner supplied no project-rule caveat."""
    full_report = _report()

    rendered_text = TextReporter().render(full_report)
    rendered_markdown = MarkdownReporter().render(full_report)
    rendered_html = HtmlReporter().render(full_report)

    assert "Scan context" not in rendered_text
    assert "**Scan context:**" not in rendered_markdown
    assert 'class="chart-section scan-context"' not in rendered_html


def test_markdown_and_html_escape_partial_context_with_normal_reporter_rules() -> None:
    """Escape untrusted caveat characters before PR or browser presentation."""
    report_with_delimiters = _report_with_partial_context(
        caveat="partial | context <outside>",
    )

    rendered_markdown = MarkdownReporter().render(report_with_delimiters)
    rendered_html = HtmlReporter().render(report_with_delimiters)

    assert "**Scan context:** partial \\| context <outside>" in rendered_markdown
    assert "partial | context &lt;outside&gt;" in rendered_html
    assert "partial | context <outside>" not in rendered_html


def test_markdown_reporter_groups_findings_and_escapes_table_pipes():
    finding = _finding(message="Do not render | as a table break", file_path="src/a|b.py")

    markdown = MarkdownReporter().render(_report((finding,)))

    assert "# gruff-py report" in markdown
    assert "src/a\\|b.py" in markdown
    assert "Do not render \\| as a table break" in markdown


def test_markdown_reporter_pillars_table_is_canonical_with_seven_columns():
    findings = (
        _finding(severity=Severity.ERROR, pillar=Pillar.SECURITY),
        _finding(
            rule_id="docs.missing-readme",
            severity=Severity.ADVISORY,
            pillar=Pillar.DOCUMENTATION,
        ),
        _finding(
            rule_id="docs.missing-docstring",
            severity=Severity.WARNING,
            pillar=Pillar.DOCUMENTATION,
        ),
    )

    markdown = MarkdownReporter().render(_report(findings))

    assert "## Pillars" in markdown
    assert "| Pillar | Grade | Score | Findings | Advisory | Warning | Error |" in markdown
    assert "| --- | --- | ---: | ---: | ---: | ---: | ---: |" in markdown
    # Sort: findings DESC then pillar ASC, so documentation (2 findings) precedes
    # security (1 finding).
    documentation_index = markdown.index("| documentation |")
    security_index = markdown.index("| security |")
    assert documentation_index < security_index
    # Score is rendered to two decimals.
    assert "| 100.00 |" in markdown


def test_markdown_reporter_pillars_table_uses_pillar_score_counts():
    """Markdown pillar rows expose the seven canonical columns with correct severity counts."""
    findings = (
        _finding(severity=Severity.ERROR, pillar=Pillar.SECURITY),
        _finding(
            rule_id="docs.missing-readme",
            severity=Severity.ADVISORY,
            pillar=Pillar.DOCUMENTATION,
        ),
        _finding(
            rule_id="docs.missing-docstring",
            severity=Severity.WARNING,
            pillar=Pillar.DOCUMENTATION,
        ),
    )

    markdown = MarkdownReporter().render(_report(findings))

    pillar_lines = [line for line in markdown.splitlines() if line.startswith("| documentation |") or line.startswith("| security |")]
    # 7 columns => 8 pipes per row.
    # gruff: disable-next=test-quality.magic-number-assertion -- 8 pipes is the contract under test.
    assert all(line.count("|") == 8 for line in pillar_lines)
    documentation_row = next(line for line in pillar_lines if line.startswith("| documentation |"))
    security_row = next(line for line in pillar_lines if line.startswith("| security |"))
    # documentation: 1 advisory + 1 warning + 0 error => findings=2, advisory=1, warning=1, error=0
    assert documentation_row.endswith("| 2 | 1 | 1 | 0 |")
    # security: 1 error => findings=1, advisory=0, warning=0, error=1
    assert security_row.endswith("| 1 | 0 | 0 | 1 |")


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

    assert payload["schemaVersion"] == "gruff-py.hotspot.v1"
    assert payload["type"] == "hotspot-map"
    assert payload["hotspots"][0]["file"] == "src/app.py"


# SARIF contract: render from native AnalysisReport and RuleRegistry only; keep
# native rule ids/fingerprints/schema strings intact; sort driver rules by rule
# id; use gruffFingerprint and gruffSchemaVersion shared with gruff-rs; normalize
# artifact URIs; omit rich SARIF constructs until native data exists.
def test_sarif_reporter_emits_rule_metadata_and_fingerprint():
    payload = json.loads(SarifReporter().render(_report()))
    driver = payload["runs"][0]["tool"]["driver"]
    result = payload["runs"][0]["results"][0]
    rule_list = driver["rules"]
    rule_ids = [rule["id"] for rule in rule_list]
    rules = {rule["id"]: rule for rule in rule_list if isinstance(rule, dict)}

    assert result["ruleId"] in rules
    _assert_sarif_driver_metadata(payload, driver, rule_ids)
    _assert_sarif_result_contract(result, rule_ids)
    _assert_sarif_rule_metadata(rules)
    _assert_sarif_shared_contract(payload)


def _assert_sarif_driver_metadata(
    payload: dict[str, Any],
    driver: dict[str, Any],
    rule_ids: list[str],
) -> None:
    assert payload["version"] == "2.1.0"
    assert driver["name"] == "gruff-py"
    assert driver["semanticVersion"] == "0.1.0-test"
    assert "informationUri" not in driver
    assert rule_ids == sorted(rule_ids)


def _baseline_identity(finding: Finding) -> str:
    """Return the durable identity a SARIF result must publish for one finding, ranking it as the run would."""
    named = finding_identities([finding])[0]
    assert named is not None
    return named.identity


def _assert_sarif_result_contract(result: dict[str, Any], rule_ids: list[str]) -> None:
    assert result["ruleId"] == "security.dangerous-function-call"
    assert result["ruleIndex"] == rule_ids.index("security.dangerous-function-call")
    assert result["level"] == "error"
    assert result["message"]["text"] == "Dangerous call to eval()."
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    # Code scanning groups alerts by the ratified durable identity, the same name baseline matching reads.
    assert result["partialFingerprints"]["gruffFingerprint"] == _baseline_identity(_report().findings[0])
    assert result["properties"]["metadata"]["target"] == "eval"


def _assert_sarif_rule_metadata(rules: dict[str, dict[str, Any]]) -> None:
    assert set(rules["security.dangerous-function-call"]) == {
        "id",
        "name",
        "shortDescription",
        "fullDescription",
        "help",
        "properties",
    }
    assert rules["security.dangerous-function-call"]["properties"]["pillar"] == "security"
    assert rules["security.dangerous-function-call"]["properties"]["defaultSeverity"] == "error"
    assert rules["security.dangerous-function-call"]["properties"]["defaultEnabled"] is True
    assert "documentation" in rules["security.dangerous-function-call"]["properties"]
    assert "size.file-length" in rules


def _assert_sarif_shared_contract(payload: dict[str, Any]) -> None:
    assert payload["runs"][0]["properties"]["gruffSchemaVersion"] == "gruff.analysis.v3"
    assert payload["runs"][0]["properties"]["score"] == _report().score.composite.score
    assert json.loads(JsonReporter().render(_report()))["schemaVersion"] == "gruff.analysis.v3"


def _unknown_rule_payload() -> dict[str, Any]:
    report = _report(
        (
            _finding(
                rule_id="external.custom-rule",
                message="External rule message.",
                severity=Severity.WARNING,
                pillar=Pillar.DESIGN,
                secondary_pillars=(Pillar.MAINTAINABILITY,),
            ),
        )
    )
    return json.loads(SarifReporter().render(report))


def test_unknown_rule_fallback_has_same_shape_as_registry_backed_rule() -> None:
    run = _unknown_rule_payload()["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    assert set(rules["external.custom-rule"]) == set(rules["security.dangerous-function-call"])


def test_unknown_rule_fallback_uses_rule_id_for_name_and_descriptions() -> None:
    run = _unknown_rule_payload()["runs"][0]
    fallback = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}["external.custom-rule"]
    assert fallback["name"] == "external.custom-rule"
    assert fallback["shortDescription"]["text"] == "external.custom-rule"
    assert fallback["fullDescription"]["text"] == "External rule message."
    assert fallback["help"]["text"] == "External rule message."


def test_unknown_rule_fallback_projects_finding_attributes_into_properties() -> None:
    run = _unknown_rule_payload()["runs"][0]
    fallback = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}["external.custom-rule"]
    assert fallback["properties"] == {
        "pillar": "design",
        "tier": "v0.1",
        "defaultSeverity": "warning",
        "confidence": "high",
        "defaultEnabled": True,
        "secondaryPillars": ["maintainability"],
    }
    assert "severity" not in fallback["properties"]


def test_unknown_rule_fallback_result_rule_index_points_to_matching_driver_rule() -> None:
    run = _unknown_rule_payload()["runs"][0]
    result = run["results"][0]
    assert run["tool"]["driver"]["rules"][result["ruleIndex"]]["id"] == result["ruleId"]


def test_sarif_reporter_projects_registry_thresholds_and_options():
    payload = json.loads(SarifReporter().render(_report()))
    rules = {rule["id"]: rule for rule in payload["runs"][0]["tool"]["driver"]["rules"] if isinstance(rule, dict)}

    assert rules["size.file-length"]["properties"]["threshold"] == 1000
    assert "thresholds" not in rules["size.file-length"]["properties"]
    assert rules["test-quality.test-longer-than-sut"]["properties"]["options"] == {
        "ratio": 2.0,
    }


def test_sarif_reporter_omits_region_when_finding_has_no_line():
    payload = json.loads(SarifReporter().render(_report((_finding(line=None),))))

    physical_location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"]

    assert physical_location["artifactLocation"]["uri"] == "src/app.py"
    assert "region" not in physical_location


_NATIVE_METADATA_FINDING_LINE = 12
_NATIVE_METADATA_FINDING_COLUMN = 8
_NATIVE_METADATA_FINDING_END_LINE = 15


def _native_metadata_finding_payload() -> dict[str, Any]:
    finding = _finding(
        line=_NATIVE_METADATA_FINDING_LINE,
        end_line=_NATIVE_METADATA_FINDING_END_LINE,
        column=_NATIVE_METADATA_FINDING_COLUMN,
        symbol="load_user",
        remediation="Use a safe dispatcher.",
        secondary_pillars=(Pillar.MAINTAINABILITY,),
        metadata={"target": "eval", "count": 2},
    )
    return json.loads(SarifReporter().render(_report((finding,))))


def test_sarif_reporter_projects_finding_region_from_native_attributes() -> None:
    result = _native_metadata_finding_payload()["runs"][0]["results"][0]
    region = result["locations"][0]["physicalLocation"]["region"]
    assert region == {
        "startLine": _NATIVE_METADATA_FINDING_LINE,
        "startColumn": _NATIVE_METADATA_FINDING_COLUMN,
        "endLine": _NATIVE_METADATA_FINDING_END_LINE,
    }


def test_sarif_reporter_projects_finding_classification_into_properties() -> None:
    properties = _native_metadata_finding_payload()["runs"][0]["results"][0]["properties"]
    assert properties["severity"] == "error"
    assert properties["pillar"] == "security"
    assert properties["tier"] == "v0.1"
    assert properties["confidence"] == "high"
    assert properties["secondaryPillars"] == ["maintainability"]


def test_sarif_reporter_projects_finding_remediation_and_metadata() -> None:
    properties = _native_metadata_finding_payload()["runs"][0]["results"][0]["properties"]
    assert properties["symbol"] == "load_user"
    assert properties["remediation"] == "Use a safe dispatcher."
    assert properties["metadata"] == {"target": "eval", "count": 2}


def test_sarif_reporter_projects_security_taxonomy_without_fingerprint_churn():
    finding = _finding(
        rule_id="security.sql-concatenation",
        message="SQL placeholder is quoted.",
        metadata={
            "target": "cursor.execute",
            "cwe": ["CWE-89"],
            "owasp": ["A03:2021-Injection"],
            "securitySeverity": "high",
            "sourceLabel": "quoted-placeholder",
            "sinkLabel": "sql-execution",
        },
    )
    payload = json.loads(SarifReporter().render(_report((finding,))))
    run = payload["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    result = run["results"][0]

    assert rules["security.sql-concatenation"]["properties"]["documentation"]["security"] == {
        "cwe": ["CWE-89"],
        "owasp": ["A03:2021-Injection"],
        "securitySeverity": "high",
    }
    assert result["properties"]["metadata"]["securitySeverity"] == "high"
    assert result["properties"]["metadata"]["sourceLabel"] == "quoted-placeholder"
    assert result["partialFingerprints"]["gruffFingerprint"] == _baseline_identity(finding)


def test_dependency_security_findings_do_not_leak_raw_references_in_reporters() -> None:
    """Dependency posture findings redact raw URL, Git, and local path references."""
    findings = tuple(_dependency_security_findings())
    report = _report(findings)
    rendered_outputs = (
        JsonReporter().render(report),
        MarkdownReporter().render(report),
        HtmlReporter().render(report),
        GithubAnnotationsReporter().render(report),
        SarifReporter().render(report),
    )
    leaked = [raw_reference for raw_reference in _RAW_DEPENDENCY_REFERENCES if any(raw_reference in output for output in rendered_outputs)]

    assert {finding.rule_id for finding in findings} == {
        "security.dependency-git-reference",
        "security.dependency-local-path",
        "security.dependency-url-reference",
    }
    assert leaked == []


def test_sensitive_data_findings_do_not_leak_raw_secrets_in_reporters() -> None:
    """Sensitive-data reporters carry only redacted previews, never raw credential values."""
    raw_secrets = (
        "AIza" + "SyA1b2C3d4E5" + "f6G7h8I9j0K1" + "l2M3n4O5p6Q",
        "rem0te" + "Secret!42",
        "abc123" + "def456" + "abc123" + "def456",
        "MIIEv" + ("A" * 120),
    )
    findings = tuple(_sensitive_data_findings())
    report = _report(findings)
    rendered_outputs = (
        TextReporter().render(report),
        JsonReporter().render(report),
        MarkdownReporter().render(report),
        HtmlReporter().render(report),
        GithubAnnotationsReporter().render(report),
        HotspotReporter().render(report),
        SarifReporter().render(report),
    )
    leaked = [raw_secret for raw_secret in raw_secrets if any(raw_secret in output for output in rendered_outputs)]

    assert {
        "sensitive-data.api-key-pattern",
        "sensitive-data.gcp-service-account-key",
        "sensitive-data.url-credentials",
    } <= {finding.rule_id for finding in findings}
    assert leaked == []


_RAW_DEPENDENCY_REFERENCES = (
    "downloads.example.test",
    "github.com/acme",
    "/opt/internal/widget",
)


def _dependency_security_findings() -> list[Finding]:
    """Return dependency-posture findings produced by the real rule registry."""
    source = """[project]
dependencies = [
    "urlpkg @ https://downloads.example.test/urlpkg-1.0.0.tar.gz",
    "gitpkg @ git+https://github.com/acme/gitpkg.git@main",
    "localpkg @ file:///opt/internal/widget",
]
"""
    return [
        finding
        for finding in RuleRegistry.defaults().analyse(
            [make_text_unit(source, "pyproject.toml")],
            default_ctx(),
        )
        if finding.rule_id.startswith("security.dependency-")
    ]


def _sensitive_data_findings() -> list[Finding]:
    """Return sensitive-data findings produced by the real rule registry."""
    google_key = "AIza" + "SyA1b2C3d4E5" + "f6G7h8I9j0K1" + "l2M3n4O5p6Q"
    url_password = "rem0te" + "Secret!42"
    private_key_id = "abc123" + "def456" + "abc123" + "def456"
    private_key_body = "MIIEv" + ("A" * 120)
    private_key_value = "-----BEGIN " + "PRIVATE KEY-----\\n" + private_key_body + "\\n-----END " + "PRIVATE KEY-----\\n"
    source = (
        f"GOOGLE_API_KEY={google_key}\n"
        f"REMOTE=https://deploy:{url_password}@api.example.test/v1\n"
        "{\n"
        '  "type": "service_account",\n'
        f'  "private_key_id": "{private_key_id}",\n'
        f'  "private_key": "{private_key_value}"\n'
        "}\n"
    )
    return [
        finding
        for finding in RuleRegistry.defaults().analyse(
            [make_text_unit(source, "secrets.env")],
            default_ctx(),
        )
        if finding.rule_id.startswith("sensitive-data.")
    ]


def test_sarif_reporter_does_not_emit_stale_contract_keys():
    rendered = SarifReporter().render(_report())
    stale_keys = (
        "partialFingerprints." + "primary",
        "gruffPy" + "Fingerprint",
        "gruffPy" + "SchemaVersion",
    )

    leaked = [key for key in stale_keys if key in rendered]
    assert leaked == [], f"stale SARIF keys leaked into output: {leaked}"


def test_sarif_reporter_normalizes_paths_and_maps_native_severities():
    report = _report(
        (
            _finding(file_path="./src\\error.py", severity=Severity.ERROR),
            _finding(file_path="./src\\warning.py", severity=Severity.WARNING),
            _finding(file_path="./src\\advisory.py", severity=Severity.ADVISORY),
        )
    )

    payload = json.loads(SarifReporter().render(report))
    results = payload["runs"][0]["results"]
    levels = [result["level"] for result in results]
    uris = [result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results]

    assert levels == ["error", "warning", "note"]
    assert uris == ["src/error.py", "src/warning.py", "src/advisory.py"]
    assert all(not uri.startswith("./") and "\\" not in uri for uri in uris)


def test_sarif_reporter_rule_indexes_point_to_sorted_driver_rules():
    payload = json.loads(SarifReporter().render(_report()))
    run = payload["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    driver_rules = run["tool"]["driver"]["rules"]

    assert rule_ids == sorted(rule_ids)
    mismatched = [
        (result["ruleIndex"], result["ruleId"], driver_rules[result["ruleIndex"]]["id"])
        for result in run["results"]
        if driver_rules[result["ruleIndex"]]["id"] != result["ruleId"]
    ]
    assert mismatched == [], f"rule index ↔ id mismatches: {mismatched}"


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


# gruff: disable-next=test-quality.multiple-aaa-cycles -- cohesive single-render check.
def test_html_reporter_pillars_table_is_canonical_with_seven_columns():
    findings = (
        _finding(severity=Severity.ERROR, pillar=Pillar.SECURITY),
        _finding(
            rule_id="docs.missing-readme",
            severity=Severity.ADVISORY,
            pillar=Pillar.DOCUMENTATION,
        ),
        _finding(
            rule_id="docs.missing-docstring",
            severity=Severity.WARNING,
            pillar=Pillar.DOCUMENTATION,
        ),
    )

    html = HtmlReporter().render(_report(findings))

    assert '<table class="pillar-list">' in html
    headers = (
        '<th scope="col">pillar</th>',
        '<th scope="col" class="num">grade</th>',
        '<th scope="col" class="num">score</th>',
        '<th scope="col" class="num">findings</th>',
        '<th scope="col" class="num">advisory</th>',
        '<th scope="col" class="num">warning</th>',
        '<th scope="col" class="num">error</th>',
    )
    header_block = "".join(headers)
    assert header_block in html
    # Sort: findings DESC then pillar ASC, so documentation (2 findings) precedes
    # security (1 finding).
    documentation_index = html.index('"file-path">documentation<')
    security_index = html.index('"file-path">security<')
    assert documentation_index < security_index
    # Score is rendered to two decimals.
    assert ">100.00<" in html


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

    assert display_filter.filter_findings(findings) == []
    assert display_filter.to_dict() == {
        "active": True,
        "minSeverity": "warning",
        "includePillars": [],
        "excludePillars": [],
        "includeRules": [],
        "excludeRules": ["security.dangerous-function-call"],
    }
