"""``sensitive-data.phi-pattern`` - US-centric protected-health-info shapes.

US SSN (``NNN-NN-NNNN``) and a simple Medical Record Number heuristic
(``MRN: <6-10 digits>`` near the word). Conservative on purpose: US-centric and
narrow patterns. The rule does NOT promise HIPAA compliance - it surfaces
shapes that warrant manual review.
"""

import re

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.sensitive_data._secret_scanner_helper import fixed_preview

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_MRN_RE = re.compile(r"\bMRN[:\s]+(\d{6,10})\b", re.IGNORECASE)
# Placeholder SSNs from US Social Security Admin examples; never real.
_SSN_PLACEHOLDERS: frozenset[str] = frozenset({"000-00-0000", "123-45-6789", "999-99-9999"})


class PhiPatternRule(SourceTextRule):
    """Detect US-shaped protected health information in source.

    Users see findings for realistic SSN literals and ``MRN: <digits>`` patterns so they can replace
    exposed data, while common documentation placeholders remain outside the report.
    """

    ID = "sensitive-data.phi-pattern"

    def definition(self) -> RuleDefinition:
        """Describe the PHI-pattern rule as a medium-confidence ERROR.

        Users receive an error for the privacy risk, but medium confidence makes clear that the
        narrow SSN and MRN shapes require review and do not promise compliance.

        Returns:
            Definition for the PHI-pattern rule under the sensitive-data
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="PHI pattern",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag US SSN literals and ``MRN: <digits>`` patterns in source.

        Canonical SSA documentation placeholders (``000-00-0000``,
        ``123-45-6789``, ``999-99-9999``) are recognised and skipped.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per non-placeholder SSN or MRN match.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Each SSN-shaped occurrence gets an independent source location in the user's report.
        for ssn_match in _SSN_RE.finditer(unit.source):
            social_security_number = ssn_match.group(0)
            # Standard documentation values stay silent because they do not identify a real person.
            if social_security_number in _SSN_PLACEHOLDERS:
                continue
            findings.append(_build_phi_finding(definition, unit, ssn_match.start(), "ssn"))
        # Every labelled medical-record number remains visible for manual privacy review.
        for medical_record_match in _MRN_RE.finditer(unit.source):
            findings.append(_build_phi_finding(definition, unit, medical_record_match.start(), "mrn"))
        return findings


def _build_phi_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    offset: int,
    kind: str,
) -> Finding:
    """Build the fixed-preview PHI finding shown at the matched user source line."""
    line = unit.source.count("\n", 0, offset) + 1
    return Finding(
        rule_id=definition.id,
        message=f"Protected health information ({kind.upper()}) shape detected.",
        file_path=unit.file.display_path,
        line=line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        remediation=(
            "Move PHI out of the repository. Use deterministic placeholders for tests and pull real values from a HIPAA-compliant store at runtime."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"preview": fixed_preview(), "kind": kind},
    )
