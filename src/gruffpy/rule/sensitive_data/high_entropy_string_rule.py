"""``sensitive-data.high-entropy-string`` - generic Shannon-entropy detector.

Walks the file looking for substrings of at least ``minLength`` base64-alphabet
characters whose Shannon entropy reaches ``entropy`` bits/char. Both are rule
thresholds with the ratified family defaults of 32 characters and 4.2 bits
(FAMILY-CONTRACT, search: ``sensitive-data.high-entropy-string`` — RATIFIED).
Suppresses common false-positive shapes: paths, PascalCase identifiers, and hex
content shorter than 40 chars (those are usually checksums or short hashes, not
secrets). A candidate never spans ``=``, so a ``KEY=value`` assignment is judged
as its key and its value rather than as one string.
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
    fixed_preview,
    shannon_entropy,
)
from gruffpy.rule.sensitive_data.api_key_pattern_rule import contains_provider_api_key

# ``=`` is outside the class: joined, ``AWS_DEFAULT_REGION=ap-southeast-2`` measured 33 characters at 4.62 bits,
# while neither half is a candidate. Base64 padding only trims the candidate, and a padded 46-character secret
# still reports.
_CANDIDATE_CHARACTERS = "[A-Za-z0-9+/_-]"
_PASCAL_CASE_RE = re.compile(r"^(?:[A-Z][a-z]+){2,}$")
_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")


class HighEntropyStringRule(SourceTextRule):
    """Detect long base64-alphabet strings above the secret entropy threshold.

    Users see a review finding for unknown random-looking literals after common benign shapes and
    provider keys are removed, with no candidate-derived text included in the preview.
    """

    ID = "sensitive-data.high-entropy-string"

    def definition(self) -> RuleDefinition:
        """Describe the high-entropy-string rule under the ratified family contract.

        Warning severity, medium confidence and enabled by default, with ``minLength`` 32 and
        ``entropy`` 4.2 as configurable thresholds, the values all five ports publish for this id.

        Returns:
            Definition for the high-entropy-string rule under the
            sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="High-entropy string",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"minLength": 32, "entropy": 4.2},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag base64-alphabet runs at least ``minLength`` long whose entropy reaches ``entropy`` bits/char.

        Users see random-looking literals after paths, identifiers, and short checksums are
        removed as common benign shapes.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context supplying the ``minLength`` and ``entropy`` thresholds.

        Returns:
            One finding per high-entropy substring that passes the
            benign-shape filter.
        """
        definition = self.definition()
        settings = context.settings_for(definition)
        # A zero-length candidate is no string at all, so a configured minLength below 1 still needs one character.
        min_length = max(1, int(settings.numeric_threshold("minLength")))
        entropy_threshold = settings.numeric_threshold("entropy")
        findings: list[Finding] = []
        # Each random-looking literal is assessed independently so users can triage its source line.
        for candidate_match in re.finditer(f"{_CANDIDATE_CHARACTERS}{{{min_length},}}", unit.source):
            secret_candidate = candidate_match.group(0)
            # Known benign shapes stay out of the report before the entropy threshold is applied.
            if _is_benign_literal(secret_candidate):
                continue
            # Lower-entropy text lacks enough secret signal to justify a user-facing warning.
            if shannon_entropy(secret_candidate) < entropy_threshold:
                continue
            line = unit.source.count("\n", 0, candidate_match.start()) + 1
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="High-entropy string - possible secret literal.",
                    file_path=unit.file.display_path,
                    line=line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "If this is genuinely a secret, rotate it and move it out of "
                        "the repository. If it is benign, confirm that judgment during review; "
                        "secret-derived preview allowlisting is not supported."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    # The rule's own thresholds already explain why this fired. The candidate's
                    # entropy and character count are statistics computed from the matched value
                    # and are forbidden in serialized output by FAMILY-CONTRACT section 5.
                    metadata={"preview": fixed_preview()},
                ),
            )
        return findings


def _is_benign_literal(candidate: str) -> bool:
    """Best-effort screen against common false-positive shapes; the candidate already meets ``minLength``."""
    if "\\" in candidate or candidate.count("/") >= 2:
        # Filesystem paths have multiple separators; one `/` is fine
        # (base64 alphabet includes `/`).
        return True
    if contains_provider_api_key(candidate):
        return True
    if _PASCAL_CASE_RE.match(candidate):
        return True
    if _HEX_RE.match(candidate) and len(candidate) < 40:
        return True
    # Snake_case identifier without numeric noise.
    return "_" in candidate and not any(c.isdigit() for c in candidate)
