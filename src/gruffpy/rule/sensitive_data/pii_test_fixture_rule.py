"""``sensitive-data.pii-test-fixture`` - realistic PII in test fixtures.

Fires on emails and phone numbers that look real (not placeholder or reserved
domains, not ``555`` US-test prefixes, not timestamp-shaped fixture numbers).
Scoped to test paths so production config containing the same patterns isn't
surfaced.
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
from gruffpy.rule.sensitive_data._secret_scanner_helper import redact_preview

_EMAIL_RE = re.compile(r"(?<!\\)\b[A-Za-z0-9._%+-]+@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(
    r"\b\+?1?[-.\s]?\(?(?P<area>\d{3})\)?[-.\s]?(?P<exchange>\d{3})[-.\s]?\d{4}\b"
)
_PLACEHOLDER_DOMAINS: frozenset[str] = frozenset(
    {
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "localhost",
        "foo.bar",
        "domain.tld",
    }
)
_RESERVED_EMAIL_TLDS: frozenset[str] = frozenset(
    {"example", "invalid", "localhost", "local", "test"}
)
# 555 in the exchange position (NXX-555-NNNN) is the canonical US placeholder
# for fictitious numbers. The area-code 555 is also reserved for directory-
# assistance use, so treat either position as a placeholder.
_PLACEHOLDER_PHONE_SEGMENTS: frozenset[str] = frozenset({"555"})
_TIMESTAMP_CONTEXT_TERMS: frozenset[str] = frozenset(
    {
        "created-at",
        "created_at",
        "created",
        "epoch",
        "expiration",
        "expires",
        "reset-at",
        "reset_at",
        "resets-at",
        "resets_at",
        "time",
        "time_ms",
        "timestamp",
        "unix",
        "updated-at",
        "updated_at",
    }
)


class PiiTestFixtureRule(SourceTextRule):
    """Detect realistic emails or phone numbers in test/fixture files (ignoring placeholders)."""

    ID = "sensitive-data.pii-test-fixture"

    def definition(self) -> RuleDefinition:
        """Describe the PII-in-test-fixture rule as a medium-confidence warning.

        Medium confidence because realistic-looking emails/phones don't
        always belong to a real person; the placeholder allowlists
        (``example.com``, reserved TLDs, ``555`` numbers, timestamp-shaped
        fixture numbers) cover the canonical fixture shapes.

        Returns:
            Definition for the PII-test-fixture rule under the
            sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="PII in test fixture",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag realistic emails and phone numbers in files under test paths.

        Path gate: the file path must contain ``test`` or ``fixture``.
        Placeholder domains (``example.com``, ``test.com``, reserved final
        labels such as ``.local`` / ``.test``), US ``555`` area / exchange
        codes, and timestamp-context bare numbers are recognised and skipped.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per realistic email or phone in a test/fixture file.
        """
        if not _is_test_path(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _EMAIL_RE.finditer(unit.source):
            value = match.group(0)
            if _is_scp_style_git_reference(unit.source, match.end(), value):
                continue
            if _is_placeholder_email_domain(match.group("domain")):
                continue
            findings.append(_build_finding(definition, unit, match.start(), value, "email"))
        for match in _PHONE_RE.finditer(unit.source):
            if (
                match.group("area") in _PLACEHOLDER_PHONE_SEGMENTS
                or match.group("exchange") in _PLACEHOLDER_PHONE_SEGMENTS
                or _is_timestamp_like_phone_match(unit.source, match)
            ):
                continue
            findings.append(
                _build_finding(definition, unit, match.start(), match.group(0), "phone")
            )
        return findings


def _is_test_path(display_path: str) -> bool:
    return "test" in display_path.lower() or "fixture" in display_path.lower()


def _is_scp_style_git_reference(source: str, match_end: int, value: str) -> bool:
    """Return whether an email-shaped match is the user/host part of a Git ref."""
    if not value.lower().startswith("git@"):
        return False
    if match_end >= len(source) or source[match_end] != ":":
        return False
    remote_path = re.split(r"[\s'\"\])}]+", source[match_end + 1 :], maxsplit=1)[0]
    return "/" in remote_path


def _is_placeholder_email_domain(domain: str) -> bool:
    """Return whether an email domain is reserved or fixture-only."""
    domain = domain.lower()
    if domain in _PLACEHOLDER_DOMAINS:
        return True
    return domain.rsplit(".", 1)[-1] in _RESERVED_EMAIL_TLDS


def _is_timestamp_like_phone_match(source: str, match: re.Match[str]) -> bool:
    """Return whether a bare phone-shaped match sits in timestamp context."""
    raw = match.group(0)
    if not raw.isdigit():
        return False
    if _is_decimal_number_fragment(source, match):
        return True
    context = _source_context_for_match(source, match)
    return any(term in context for term in _TIMESTAMP_CONTEXT_TERMS)


def _is_decimal_number_fragment(source: str, match: re.Match[str]) -> bool:
    before = source[match.start() - 1] if match.start() > 0 else ""
    after = source[match.end()] if match.end() < len(source) else ""
    after_next = source[match.end() + 1] if match.end() + 1 < len(source) else ""
    return before == "." or (after == "." and after_next.isdigit())


def _source_context_for_match(source: str, match: re.Match[str]) -> str:
    line_start = _context_line_start(source, match.start(), previous_lines=2)
    line_end = source.find("\n", match.end())
    if line_end == -1:
        line_end = len(source)
    window_start = max(0, match.start() - 40)
    window_end = min(len(source), match.end() + 40)
    return f"{source[line_start:line_end]} {source[window_start:window_end]}".lower()


def _context_line_start(source: str, offset: int, previous_lines: int) -> int:
    start = source.rfind("\n", 0, offset)
    for _ in range(previous_lines):
        if start <= 0:
            return 0
        start = source.rfind("\n", 0, start)
    return start + 1


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
        message=f"Realistic {kind} in test fixture (not a placeholder).",
        file_path=unit.file.display_path,
        line=line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        remediation=(
            "Replace with documented placeholders (`user@example.com`, `user@app.test`, "
            "`+1-555-...`) so test failures don't expose third-party PII."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"preview": redact_preview(value), "kind": kind},
    )
