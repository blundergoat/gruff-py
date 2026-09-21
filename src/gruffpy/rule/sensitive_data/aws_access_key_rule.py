"""``sensitive-data.aws-access-key`` - AWS access key ID literal.

Pattern: ``AKIA`` + 16 uppercase alphanumeric chars. AWS access key IDs are
20-character strings starting with ``AKIA`` (long-term keys) or ``ASIA``
(session tokens). Both shapes fire, including the key AWS publishes in its own
documentation: the family reports it in every port, because a key-shaped value
ending in ``EXAMPLE`` is one alphanumeric run and nothing in it marks a placeholder.
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
    category_preview,
    compile_pattern,
    iter_matches,
)

_PATTERN = compile_pattern(r"(?:AKIA|ASIA)[A-Z0-9]{16}")
# A masked key is one whose whole body is a run of X, written to show where a key goes (FAMILY-CONTRACT.md
# section 5). Only the whole body counts: a real key may contain a run of X, and hiding it would hide a live
# credential.
_MASKED_BODY = "X" * 16


class AwsAccessKeyRule(SourceTextRule):
    """Detect AWS access key IDs matching the ``AKIA`` or ``ASIA`` shape.

    Users encounter this rule when a scan finds a likely long-term or session credential and can
    use the reported source line to remove and rotate it without seeing key fragments in output.
    """

    ID = "sensitive-data.aws-access-key"

    def definition(self) -> RuleDefinition:
        """Describe the AWS-access-key rule as a high-confidence ERROR.

        Precise ``AKIA`` and ``ASIA`` shapes give users high-confidence findings, while error
        severity reflects the rotation urgency of an exposed AWS credential.

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
        """Scan raw source for ``AKIA``-/``ASIA``-prefixed access key IDs.

        Users see each key-shaped literal, AWS's documented example key among them, so a reviewer
        decides what is a placeholder rather than the suffix of the value deciding it.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per AWS access key literal.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Every key-shaped occurrence remains separately visible so users can rotate each exposure.
        for access_key_match in iter_matches(_PATTERN, unit.source):
            if access_key_match.raw[4:] == _MASKED_BODY:
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="AWS access key ID literal in source.",
                    file_path=unit.file.display_path,
                    line=access_key_match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Remove the hard-coded credential, rotate the AWS key, and load "
                        "credentials from environment variables or the AWS credentials chain."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": category_preview("aws-access-key")},
                ),
            )
        return findings
