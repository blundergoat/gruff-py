"""``sensitive-data.phi-pattern`` — US-centric protected-health-info shapes.

US SSN (``NNN-NN-NNNN``) and a simple Medical Record Number heuristic
(``MRN: <6-10 digits>`` near the word). Conservative on purpose: US-centric and
narrow patterns. The rule does NOT promise HIPAA compliance — it surfaces
shapes that warrant manual review.
"""

import re

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import SourceTextRule
from gruff.rule.sensitive_data._secret_scanner_helper import redact_preview

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_MRN_RE = re.compile(r"\bMRN[:\s]+(\d{6,10})\b", re.IGNORECASE)
# Placeholder SSNs from US Social Security Admin examples; never real.
_SSN_PLACEHOLDERS: frozenset[str] = frozenset({"000-00-0000", "123-45-6789", "999-99-9999"})


class PhiPatternRule(SourceTextRule):
    ID = "sensitive-data.phi-pattern"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="PHI pattern",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        definition = self.definition()
        findings: list[Finding] = []
        for match in _SSN_RE.finditer(unit.source):
            value = match.group(0)
            if value in _SSN_PLACEHOLDERS:
                continue
            findings.append(_build_finding(definition, unit, match.start(), value, "ssn"))
        for match in _MRN_RE.finditer(unit.source):
            value = match.group(1)
            findings.append(_build_finding(definition, unit, match.start(), value, "mrn"))
        return findings


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    offset: int,
    value: str,
    kind: str,
) -> Finding:
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
            "Move PHI out of the repository. Use deterministic placeholders for tests "
            "and pull real values from a HIPAA-compliant store at runtime."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"preview": redact_preview(value), "kind": kind},
    )
