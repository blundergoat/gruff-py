import json
from typing import Any

from gruff.analysis.report import AnalysisReport
from gruff.finding.finding import Finding
from gruff.finding.severity import Severity


class SarifReporter:
    def render(self, report: AnalysisReport) -> str:
        rules: dict[str, dict[str, Any]] = {}
        for finding in report.findings:
            rules.setdefault(
                finding.rule_id,
                {
                    "id": finding.rule_id,
                    "name": finding.rule_id,
                    "shortDescription": {"text": finding.rule_id},
                    "properties": {
                        "pillar": finding.pillar.value,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence.value,
                        "tier": finding.tier.value,
                    },
                },
            )

        rule_ids = sorted(rules)
        rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gruff",
                            "version": report.tool_version,
                            "informationUri": "https://github.com/",
                            "rules": [rules[rule_id] for rule_id in rule_ids],
                        }
                    },
                    "results": [
                        _result(finding, rule_indexes[finding.rule_id])
                        for finding in report.findings
                    ],
                }
            ],
        }
        return json.dumps(payload, indent=4) + "\n"


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _level(finding.severity),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                    "region": {"startLine": finding.line or 1},
                }
            }
        ],
        "partialFingerprints": {"gruffFingerprint": finding.fingerprint()},
        "properties": {
            "symbol": finding.symbol,
            "pillar": finding.pillar.value,
            "metadata": dict(finding.metadata),
        },
    }


def _level(severity: Severity) -> str:
    return {
        Severity.ERROR: "error",
        Severity.WARNING: "warning",
        Severity.ADVISORY: "note",
    }[severity]
