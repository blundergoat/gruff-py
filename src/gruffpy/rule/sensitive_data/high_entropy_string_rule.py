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
_PEM_ARMOUR_OPENING = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----")
# Any opening or closing marker, so a block can end only at the next one.
_PEM_ARMOUR_MARKER = re.compile(r"-----(BEGIN|END) ([A-Z0-9 ]+)-----")
# A PEM body's lines break at real line breaks and at the escaped ones a string literal spells. Each line then loses
# its concatenation operators, and its quotes, commas, brackets, comment stars and ASCII whitespace, before
# _PEM_BODY_LINE judges what is left. The operator pattern looks around one character so it stays linear.
_PEM_BODY_LINE_BREAKS = re.compile(r"\n|\\[nrt]")
_PEM_BODY_OPERATORS = re.compile(r"(?<=[ \t\r\f\x0b])[+.]|[+.](?=[ \t\r\f\x0b])")
_PEM_BODY_QUOTING = re.compile(r"[ \t\r\f\x0b\"'`,;()\[\]{}#*\\]")
_PEM_BODY_LINE = re.compile(r"[A-Za-z0-9+/]+={0,2}|=[A-Za-z0-9+/]{4}|(?:Version|Comment|Hash|Charset|MessageID|Proc-Type|DEK-Info):.*")
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
        armoured = _public_armour_spans(unit.source)
        # Each random-looking literal is assessed independently so users can triage its source line.
        for candidate_match in re.finditer(f"{_CANDIDATE_CHARACTERS}{{{min_length},}}", unit.source):
            secret_candidate = candidate_match.group(0)
            # A public PEM block's base64 body is certificate or public-key material, never a secret.
            if any(start <= candidate_match.start() < end for start, end in armoured):
                continue
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


def _public_armour_spans(source: str) -> list[tuple[int, int]]:
    """Return the offset spans of the PEM blocks whose label names no private key.

    A certificate, public key, certificate request, PKCS7 bundle or CRL is public by construction, so its body is
    never a secret. A block ends at the next marker, which must close the same label, and its body must be
    PEM-shaped. Anything else means the markers are not a block, so nothing between them is exempted and a private
    key there stays scannable (FAMILY-CONTRACT section 12).

    Args:
        source: The file text being scanned.

    Returns:
        Half-open ``(start, end)`` offsets, from each opening marker to the end of its closing marker.
    """
    spans: list[tuple[int, int]] = []
    for opening in _PEM_ARMOUR_OPENING.finditer(source):
        label = opening.group(1)
        if "PRIVATE" in label:
            continue
        closing = _PEM_ARMOUR_MARKER.search(source, opening.end())
        if closing is None or closing.group(1) != "END" or closing.group(2) != label:
            continue
        if _is_pem_shaped(source[opening.end() : closing.start()]):
            spans.append((opening.start(), closing.end()))
    return spans


def _is_pem_shaped(body: str) -> bool:
    """Report whether every line between two markers is base64, a PGP checksum, an armour header or empty.

    Args:
        body: The text between an opening marker and its closing marker.

    Returns:
        False when any line, once its string quoting is stripped, is code, a placeholder or prose.
    """
    # Splitting at escaped line breaks too keeps a one-line block's header from vouching for the rest of the line.
    for segment in _PEM_BODY_LINE_BREAKS.split(body):
        line = _PEM_BODY_QUOTING.sub("", _PEM_BODY_OPERATORS.sub("", segment))
        if line and _PEM_BODY_LINE.fullmatch(line) is None:
            return False
    return True


def _is_benign_literal(candidate: str) -> bool:
    """Best-effort screen against common false-positive shapes; the candidate already meets ``minLength``."""
    if "\\" in candidate or candidate.count("/") >= 2:
        # Filesystem paths have multiple separators; one `/` is fine
        # (base64 alphabet includes `/`).
        return True
    if not _has_letter_and_digit(candidate):
        # FAMILY-CONTRACT section 12: without a letter and a digit a literal is not credential-shaped.
        return True
    if contains_provider_api_key(candidate):
        return True
    if _PASCAL_CASE_RE.match(candidate):
        return True
    if _HEX_RE.match(candidate) and len(candidate) < 40:
        return True
    # Snake_case identifier without numeric noise.
    return "_" in candidate and not any(c.isdigit() for c in candidate)


def _has_letter_and_digit(candidate: str) -> bool:
    """Report whether a literal carries at least one letter and at least one digit.

    FAMILY-CONTRACT section 12 sets this floor for all five ports: a run of one character class, such as random-letter
    test data or a MIME type, clears the entropy bar by construction, and a digit-free mix of cases is an identifier.

    Args:
        candidate: The literal being classified.

    Returns:
        True when the literal holds both a letter and a digit.
    """
    has_letter = any("a" <= character <= "z" or "A" <= character <= "Z" for character in candidate)
    return has_letter and any("0" <= character <= "9" for character in candidate)
