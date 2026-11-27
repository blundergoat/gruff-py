"""Check source for AWS access key ID literals under `sensitive-data.aws-access-key`.

Long-term and session access key IDs are checked even when present on the same line.
The exact vendor-documented access key example and fully masked bodies stay quiet.
Findings show a fixed preview and the source location for the reviewer to inspect.
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
        """Describe the AWS-access-key rule as a high-confidence warning.

        Precise ``AKIA`` and ``ASIA`` shapes give users high-confidence findings, while warning
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
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report candidate AWS access key IDs in the selected source file.
        Keep each location visible for review while the preview masks the matched key.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per access key match remaining after the documented-sample and masked-value exclusions.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Report each source location even when every finding has the same redacted AWS preview.
        for access_key_match in iter_matches(_PATTERN, unit.source):
            # A developer may paste a fully masked key into documentation. It contains no key ID to investigate.
            if access_key_match.raw[4:] == _MASKED_BODY:
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="AWS access key ID literal in source.",
                    file_path=unit.file.display_path,
                    line=access_key_match.line,
                    column=access_key_match.column,
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
