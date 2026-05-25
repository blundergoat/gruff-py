import json
from dataclasses import dataclass, replace
from typing import Any

from gruffpy.analysis.report import AnalysisReport
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
from gruffpy.scoring.score_calculator import ScoreCalculator


@dataclass(frozen=True, slots=True)
class _FindingSpec:
    """Finding factory inputs for reporter tests."""

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

    pillar_lines = [
        line
        for line in markdown.splitlines()
        if line.startswith("| documentation |") or line.startswith("| security |")
    ]
    # 7 columns => 8 pipes per row.
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


def _assert_sarif_result_contract(result: dict[str, Any], rule_ids: list[str]) -> None:
    assert result["ruleId"] == "security.dangerous-function-call"
    assert result["ruleIndex"] == rule_ids.index("security.dangerous-function-call")
    assert result["level"] == "error"
    assert result["message"]["text"] == "Dangerous call to eval()."
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert result["partialFingerprints"]["gruffFingerprint"] == _report().findings[0].fingerprint()
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
    assert payload["runs"][0]["properties"]["gruffSchemaVersion"] == "gruff-py.analysis.v1"
    assert payload["runs"][0]["properties"]["score"] == _report().score.composite.score
    assert json.loads(JsonReporter().render(_report()))["schemaVersion"] == "gruff-py.analysis.v1"


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
    rules = {
        rule["id"]: rule
        for rule in payload["runs"][0]["tool"]["driver"]["rules"]
        if isinstance(rule, dict)
    }

    assert rules["size.file-length"]["properties"]["thresholds"] == {
        "warning": 1000,
        "error": 1000,
    }
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
    fingerprint = finding.fingerprint()

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
    assert result["partialFingerprints"]["gruffFingerprint"] == fingerprint


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
    uris = [
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for result in results
    ]

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
