"""``sensitive-data.high-entropy-string`` — generic Shannon-entropy detector.

Walks the file looking for substrings of at least 20 base64-alphabet characters
whose Shannon entropy exceeds 4.5 bits/char. Suppresses common false-positive
shapes: paths, PascalCase identifiers, and hex content shorter than 40 chars
(those are usually checksums or short hashes, not secrets).
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
from gruffpy.rule.sensitive_data._secret_scanner_helper import (
    redact_preview,
    shannon_entropy,
)

_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_ENTROPY_THRESHOLD = 4.5
_PASCAL_CASE_RE = re.compile(r"^(?:[A-Z][a-z]+){2,}$")
_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
_MIN_LENGTH = 20


class HighEntropyStringRule(SourceTextRule):
    ID = "sensitive-data.high-entropy-string"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="High-entropy string",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.LOW,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        definition = self.definition()
        findings: list[Finding] = []
        for match in _CANDIDATE_RE.finditer(unit.source):
            candidate = match.group(0)
            if _looks_benign(candidate):
                continue
            if shannon_entropy(candidate) < _ENTROPY_THRESHOLD:
                continue
            line = unit.source.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="High-entropy string — possible secret literal.",
                    file_path=unit.file.display_path,
                    line=line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "If this is genuinely a secret, rotate it and move it out of "
                        "the repository. If it's a benign identifier, add the preview to "
                        "`allowlists.secretPreviews` to suppress future findings."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "preview": redact_preview(candidate),
                        "entropy": round(shannon_entropy(candidate), 2),
                        "length": len(candidate),
                    },
                ),
            )
        return findings


def _looks_benign(candidate: str) -> bool:
    """Best-effort screen against common false-positive shapes."""
    if len(candidate) < _MIN_LENGTH:
        return True
    if "\\" in candidate or candidate.count("/") >= 2:
        # Filesystem paths have multiple separators; one `/` is fine
        # (base64 alphabet includes `/`).
        return True
    if _PASCAL_CASE_RE.match(candidate):
        return True
    if _HEX_RE.match(candidate) and len(candidate) < 40:
        return True
    # Snake_case identifier without numeric noise.
    return "_" in candidate and not any(c.isdigit() for c in candidate)
