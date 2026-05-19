"""Renders an AnalysisReport as a SARIF 2.1.0 log for code-scanning consumers."""

import json
from typing import Any

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.schema import ANALYSIS_SCHEMA_VERSION
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
        rules: dict[str, dict[str, Any]] = {
            rule.definition().id: _rule_metadata(rule.definition())
            for rule in RuleRegistry.defaults().all()
        }
        for finding in report.findings:
            rules.setdefault(finding.rule_id, _fallback_rule_metadata(finding))

        rule_ids = sorted(rules)
        rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "semanticVersion": report.tool_version,
                            "rules": [rules[rule_id] for rule_id in rule_ids],
                        }
                    },
                    "results": [
                        _result(finding, rule_indexes[finding.rule_id])
                        for finding in report.findings
                    ],
                    "properties": _run_properties(report),
                }
            ],
        }
        return json.dumps(payload, indent=4) + "\n"


def _rule_metadata(definition: RuleDefinition) -> dict[str, Any]:
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
            **(
                {"secondaryPillars": [pillar.value for pillar in definition.secondary_pillars]}
                if definition.secondary_pillars
                else {}
            ),
            **(
                {"thresholds": dict(definition.default_thresholds)}
                if definition.default_thresholds
                else {}
            ),
            **({"options": dict(definition.default_options)} if definition.default_options else {}),
        },
    }


def _fallback_rule_metadata(finding: Finding) -> dict[str, Any]:
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
            **(
                {"secondaryPillars": [pillar.value for pillar in finding.secondary_pillars]}
                if finding.secondary_pillars
                else {}
            ),
        },
    }


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
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

    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": _physical_location(finding),
            }
        ],
        "partialFingerprints": {"gruffFingerprint": finding.fingerprint()},
        "properties": properties,
    }


def _physical_location(finding: Finding) -> dict[str, Any]:
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
    normalized = file_path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _run_properties(report: AnalysisReport) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "gruffSchemaVersion": ANALYSIS_SCHEMA_VERSION,
    }
    if report.score is not None:
        properties["score"] = report.score.composite.score
        properties["grade"] = report.score.composite.letter
    return properties


def _level(severity: Severity) -> str:
    return {
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.ADVISORY: "note",
    }[severity]
