"""Renders an AnalysisReport as a SARIF 2.1.0 log for code-scanning consumers."""

import json
from typing import Any

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.schema import ANALYSIS_SCHEMA_VERSION
from gruffpy.finding.baseline_identity import finding_identities
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.rule.catalog import documentation_for_rule
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.registry import RuleRegistry
from gruffpy.version import TOOL_NAME


class SarifReporter:
    """Render an analysis report as a SARIF 2.1.0 log for GitHub Code Scanning / IDE consumers."""

    def render(self, report: AnalysisReport) -> str:
        """Render a SARIF 2.1.0 log for code-scanning and IDE consumers.

        Include metadata for every default-registry rule and fallback descriptors for unregistered rules found in normal or suppressed findings.

        Args:
            report: Report whose findings, suppressed findings, diagnostics and run properties populate the SARIF log.

        Returns:
            Pretty-printed SARIF JSON, trailing newline included.
        """
        rules: dict[str, dict[str, Any]] = {rule.definition().id: _rule_metadata(rule.definition()) for rule in RuleRegistry.defaults().all()}
        for finding in (*report.findings, *(item.finding for item in report.suppressed_findings)):
            rules.setdefault(finding.rule_id, _fallback_rule_metadata(finding))

        rule_ids = sorted(rules)
        rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
        run: dict[str, Any] = {
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "semanticVersion": report.tool_version,
                    "rules": [rules[rule_id] for rule_id in rule_ids],
                }
            },
            "results": [
                *(_result(finding, rule_indexes[finding.rule_id]) for finding in report.findings),
                # A finding another tool's comment or a repeated claim removed stays a result marked suppressed, so a
                # code-scanning tool shows it as suppressed rather than fixed (FAMILY-CONTRACT.md section 13c).
                *(
                    {
                        **_result(item.finding, rule_indexes[item.finding.rule_id]),
                        "suppressions": [{"kind": "inSource", "justification": item.justification}],
                    }
                    for item in report.suppressed_findings
                ),
            ],
            "properties": _run_properties(report),
        }
        if report.diagnostics:
            run["invocations"] = [
                {
                    "executionSuccessful": all(diagnostic.invalidates_run is False for diagnostic in report.diagnostics),
                    "toolExecutionNotifications": [_diagnostic_notification(diagnostic) for diagnostic in report.diagnostics],
                }
            ]
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [run],
        }
        return json.dumps(payload, indent=4) + "\n"


def _diagnostic_notification(diagnostic: RunDiagnostic) -> dict[str, Any]:
    """Convert a run diagnostic into a SARIF tool execution notification.

    Use note only for invalidates_run=False, otherwise error, matching render's executionSuccessful check.
    Prefer nonempty file_path over path; add startLine only when a path is selected and a line is known.

    Args:
        diagnostic: Run problem to report; its type becomes the descriptor id and its message the notification text.

    Returns:
        Notification mapping with descriptor, level and message. A selected path adds one location, even when the input path is an empty string.
        When the selected path is None, the locations key is omitted.
    """
    notification: dict[str, Any] = {
        "descriptor": {"id": diagnostic.type},
        "level": "note" if diagnostic.invalidates_run is False else "error",
        "message": {"text": diagnostic.message},
    }
    path = diagnostic.file_path or diagnostic.path
    if path is not None:
        physical_location: dict[str, Any] = {"artifactLocation": {"uri": _uri(path)}}
        if diagnostic.line is not None:
            physical_location["region"] = {"startLine": diagnostic.line}
        notification["locations"] = [{"physicalLocation": physical_location}]
    return notification


def _rule_metadata(definition: RuleDefinition) -> dict[str, Any]:
    """Build a default-registry SARIF rule descriptor from its definition and catalogue documentation.

    Descriptions and help use the rule description, catalogue rationale and fix guidance; optional settings appear only when present.

    Args:
        definition: Registered rule definition whose id also selects the catalogue documentation.

    Returns:
        Rule descriptor mapping with id, name, descriptions, help and a properties bag holding pillar, tier, default severity, confidence, default
        enablement and the documentation payload.
    """
    documentation = documentation_for_rule(definition.id)
    return {
        "id": definition.id,
        "name": definition.name,
        "shortDescription": {"text": definition.get_description()},
        "fullDescription": {"text": documentation.rationale},
        "help": {"text": f"{documentation.rationale}\n\n{documentation.fix_guidance}"},
        "properties": {
            "pillar": definition.pillar.value,
            "tier": definition.tier.value,
            "defaultSeverity": definition.default_severity.value,
            "confidence": definition.confidence.value,
            "defaultEnabled": definition.default_enabled,
            "documentation": documentation.to_payload(),
            **({"secondaryPillars": [pillar.value for pillar in definition.secondary_pillars]} if definition.secondary_pillars else {}),
            **definition.threshold_payload(),
            **({"options": dict(definition.default_options)} if definition.default_options else {}),
        },
    }


def _fallback_rule_metadata(finding: Finding) -> dict[str, Any]:
    """Build a stand-in rule descriptor from a finding for use when the default registry has no descriptor for its rule ID.

    The name and short description use the rule ID; full description and help use the message. Documentation, thresholds and options are omitted.
    For each unknown rule ID, render retains the first descriptor, considering reported findings before suppressed findings.

    Args:
        finding: Finding whose rule id, message and classification stand in for the missing rule definition.

    Returns:
        Rule descriptor mapping with id, name, descriptions, help and a properties bag holding pillar, tier, default severity, confidence and any
        secondary pillars from the finding, plus defaultEnabled fixed at True.
    """
    return {
        "id": finding.rule_id,
        "name": finding.rule_id,
        "shortDescription": {"text": finding.rule_id},
        "fullDescription": {"text": finding.message},
        "help": {"text": finding.message},
        "properties": {
            "pillar": finding.pillar.value,
            "tier": finding.tier.value,
            "defaultSeverity": finding.severity.value,
            "confidence": finding.confidence.value,
            "defaultEnabled": True,
            **({"secondaryPillars": [pillar.value for pillar in finding.secondary_pillars]} if finding.secondary_pillars else {}),
        },
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    """Convert one finding into a SARIF result that points back to its rule descriptor and source location.

    Symbol, remediation, secondary pillars and metadata are copied into properties only when the finding has them. This function never adds
    suppressions; render adds them to results built from suppressed findings.

    Args:
        finding: Finding to render as a result.
        rule_index: Position of the finding's rule descriptor in the sorted driver rules array.

    Returns:
        Result mapping with ruleId, ruleIndex, level, message, one physical location and properties, plus partialFingerprints only when the finding
        has a durable identity.
    """
    properties: dict[str, Any] = {
        "severity": finding.severity.value,
        "pillar": finding.pillar.value,
        "tier": finding.tier.value,
        "confidence": finding.confidence.value,
    }
    if finding.secondary_pillars:
        properties["secondaryPillars"] = [pillar.value for pillar in finding.secondary_pillars]
    if finding.symbol is not None:
        properties["symbol"] = finding.symbol
    if finding.remediation is not None:
        properties["remediation"] = finding.remediation
    if finding.metadata:
        properties["metadata"] = dict(finding.metadata)

    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": _physical_location(finding),
            }
        ],
    }
    fingerprints = _partial_fingerprints(finding)
    # A sensitive finding carries no fingerprints at all, so no secret gets a durable name in code scanning.
    if fingerprints is not None:
        result["partialFingerprints"] = fingerprints
    result["properties"] = properties
    return result


def _partial_fingerprints(finding: Finding) -> dict[str, str] | None:
    """Return the durable identity used to group SARIF alerts, or None when the finding cannot be named.

    Stored identities preserve the pipeline's declaration ranking across line moves; the fallback ranks only the supplied finding.

    Args:
        finding: Finding being rendered as a SARIF result.

    Returns:
        A partialFingerprints mapping; without a stored identity, None for sensitive findings or symbols containing the reserved ordinal separator.
    """
    # Reuse the pipeline identity after filtering so declaration ranks do not change with the remaining result set.
    if finding.baseline_identity is not None:
        return {"gruffFingerprint": finding.baseline_identity}
    named = finding_identities([finding])[0]
    return None if named is None else {"gruffFingerprint": named.identity}


def _physical_location(finding: Finding) -> dict[str, Any]:
    """Build the SARIF physical location for a finding's file and, when it has a line, its source region.

    The column and end line are added to the region only alongside a start line; a finding without a line keeps only the file location, even when it
    has a column or end line.

    Args:
        finding: Finding whose file path, line, column and end line locate the result.

    Returns:
        Physical location mapping with an artifact location, and a region only when the finding has a line.
    """
    location: dict[str, Any] = {
        "artifactLocation": {"uri": _uri(finding.file_path)},
    }
    if finding.line is not None:
        region: dict[str, int] = {"startLine": finding.line}
        if finding.column is not None:
            region["startColumn"] = finding.column
        if finding.end_line is not None:
            region["endLine"] = finding.end_line
        location["region"] = region
    return location


def _uri(file_path: str) -> str:
    """Normalise a file path into the forward-slash form written as a SARIF artifact location URI.

    Backslashes become forward slashes and every leading ./ segment is stripped. The path is not percent-encoded and an absolute path stays absolute.

    Args:
        file_path: Finding or diagnostic path as recorded by the analysis run.

    Returns:
        Normalised path string used verbatim as the artifactLocation uri.
    """
    normalized = file_path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _run_properties(report: AnalysisReport) -> dict[str, Any]:
    """Build the run-level properties bag that carries the gruff analysis schema version and, for a scored report, its composite score and grade.

    Args:
        report: Analysis report whose score, when present, supplies the composite score and letter grade.

    Returns:
        Properties mapping that always holds gruffSchemaVersion. It holds score and grade only when the report has a composite score; an unscored
        report omits both keys.
    """
    properties: dict[str, Any] = {
        "gruffSchemaVersion": ANALYSIS_SCHEMA_VERSION,
    }
    if report.score is not None and report.score.composite is not None:
        properties["score"] = report.score.composite.score
        properties["grade"] = report.score.composite.letter
    return properties


def _level(severity: Severity) -> str:
    """Map a gruff severity to the SARIF result level, with advisory findings reported as note.

    Args:
        severity: Finding severity to translate.

    Returns:
        SARIF level string: error for error, warning for warning, note for advisory.
    """
    return {
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.ADVISORY: "note",
    }[severity]
