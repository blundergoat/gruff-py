"""``sensitive-data.aws-access-key`` — AWS access key ID literal.

Pattern: ``AKIA`` + 16 uppercase alphanumeric chars. AWS access key IDs are
20-character strings starting with ``AKIA`` (long-term keys) or ``ASIA``
(session tokens). Both shapes fire, except documentation placeholders ending
in ``EXAMPLE``.
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.sensitive_data._secret_scanner_helper import (
    compile_pattern,
    iter_matches,
    redact_preview,
)

_PATTERN = compile_pattern(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
_DOCUMENTATION_SUFFIX = "EXAMPLE"


class AwsAccessKeyRule(SourceTextRule):
    ID = "sensitive-data.aws-access-key"

    def definition(self) -> RuleDefinition:
        """Describe the AWS-access-key rule as a high-confidence ERROR.

        ERROR severity reflects the blast radius of a leaked AWS root or
        session credential; ``AKIA``/``ASIA`` patterns are precise enough
        for high confidence.

        Returns:
            Definition for the AWS-access-key rule under the sensitive-data
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="AWS access key",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan raw source for ``AKIA``-/``ASIA``-prefixed access key IDs, excluding ``*EXAMPLE``.

        AWS's documentation explicitly uses ``AKIAIOSFODNN7EXAMPLE`` and
        similar placeholders, so any match ending in ``EXAMPLE`` is treated
        as canonical doc text rather than a leak.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per non-placeholder AWS access key literal.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            if match.raw.upper().endswith(_DOCUMENTATION_SUFFIX):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="AWS access key ID literal in source.",
                    file_path=unit.file.display_path,
                    line=match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Remove the hard-coded credential, rotate the AWS key, and load "
                        "credentials from environment variables or the AWS credentials chain."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redact_preview(match.raw)},
                ),
            )
        return findings
