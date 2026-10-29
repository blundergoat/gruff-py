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
        """Render *report* as a SARIF 2.1.0 log for GitHub Code Scanning / IDE consumers.

        Builds the ``runs[0].tool.driver.rules`` section from the full
        registry so SARIF consumers see metadata for every rule that
        *could* fire, not just the ones with findings. Findings without a
        matching registry entry get a fallback rule descriptor.

        Args:
            report: Fully-populated analysis report.

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
    """Convert one run diagnostic into a SARIF tool execution notification so code-scanning consumers see problems with the run itself.

    The level is note only when invalidates_run is exactly False. True and the unset None legacy fatal default both become error, which matches the
    test render uses for executionSuccessful. The location uses the diagnostic's file path in preference to its input path, and the line becomes a
    region startLine only when one of those paths is present.

    Args:
        diagnostic: Run problem to report; its type becomes the descriptor id and its message the notification text.

    Returns:
        Notification mapping with descriptor, level and message, plus a single-entry locations list only when the diagnostic names a file or input
        path; a run-wide diagnostic carries no locations key.
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
    """Build the SARIF rule descriptor for a rule in the default registry from its definition and catalogue documentation.

    The short description is the definition's description, or its name when the description is empty. The full description is the documented
    rationale, and the help text is the rationale followed by a blank line and the fix guidance. Secondary pillars, threshold keys and default options
    are added to properties only when the definition has them.

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
    """Build a stand-in rule descriptor from a finding whose rule id has no default-registry entry.

    It gives the finding's result a rule to index. The name and short description repeat the rule id, the full description and help repeat the
    finding's message, and the default severity is the finding's own severity. The descriptor always reports defaultEnabled as True and carries no
    documentation, thresholds or options. When several findings share an unregistered rule id, render keeps the descriptor built from the first one,
    reported findings before suppressed ones.

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
    """Return the fingerprints GitHub code scanning groups alerts by, or ``None`` when the result must carry none.

    ``gruffFingerprint`` is the ratified durable identity and nothing else, so an alert survives a line move while a
    second declaration of one name opens its own alert.

    Args:
        finding: Finding being rendered as a SARIF result.

    Returns:
        The ``partialFingerprints`` object, or ``None`` for a sensitive finding, which has no durable name at all.
    """
    # The pipeline names every finding before the baseline filters any; a direct API caller's finding is named here,
    # ranked by its own line, so an ordinary result is never published without a fingerprint.
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
