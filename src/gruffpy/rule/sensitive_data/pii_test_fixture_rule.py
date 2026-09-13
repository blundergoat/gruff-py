"""``sensitive-data.pii-test-fixture`` - realistic PII in test fixtures.

Fires on emails and phone numbers that look real (not placeholder or reserved
domains, not ``555`` US-test prefixes, not timestamp-shaped fixture numbers).
Scoped to explicit test and fixture path conventions so unrelated parent names
cannot turn production metadata into a fixture finding.
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
from gruffpy.rule.sensitive_data._secret_scanner_helper import category_preview

_EMAIL_RE = re.compile(r"(?<!\\)\b[A-Za-z0-9._%+-]+@(?P<domain>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_PHONE_RE = re.compile(r"\b\+?1?[-.\s]?\(?(?P<area>\d{3})\)?[-.\s]?(?P<exchange>\d{3})[-.\s]?\d{4}\b")
_TEST_FIXTURE_DIRECTORY_NAMES: frozenset[str] = frozenset({"fixture", "fixtures", "test", "test-data", "test_data", "testdata", "testing", "tests"})
# Compound directories such as `integration_tests` end in one of these tokens;
# an incidental qualifier such as `test-scan-repos` does not.
_TEST_FIXTURE_DIRECTORY_SUFFIX_TOKENS: frozenset[str] = frozenset({"fixture", "fixtures", "test", "tests"})
_SEQUENTIAL_DIGIT_FIXTURES: frozenset[str] = frozenset({"0123456789", "1234567890"})
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
_RESERVED_EMAIL_TLDS: frozenset[str] = frozenset({"example", "invalid", "localhost", "local", "test"})
# 555 in the exchange position (NXX-555-NNNN) is the canonical US placeholder.

# Area-code 555 is also reserved for directory assistance.
# Either position therefore means the user has supplied a placeholder.
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
    """Detect realistic emails or phone numbers in test and fixture files.

    Users see a finding after a test contains contact details that do not match safe fixture
    conventions, while reserved domains, 555 numbers, and numeric test data remain quiet.
    """

    ID = "sensitive-data.pii-test-fixture"

    def definition(self) -> RuleDefinition:
        """Describe the PII-in-test-fixture rule as a medium-confidence warning.

        Users receive a warning because realistic contact details may still be synthetic; reserved
        domains, 555 numbers, timestamps, and known sequences remove common fixture shapes.

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

        Users see contact-shaped values only in recognized test locations after safe domains,
        555 numbers, timestamps, and known numeric fixtures are removed.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per realistic email or phone in a test/fixture file.
        """
        # Production files remain outside this fixture-specific signal even when a parent path
        # happens to contain text such as ``test-scan-repos``.
        if not _is_test_fixture_path(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        # Each realistic email remains a separate reviewable fixture occurrence.
        for email_match in _EMAIL_RE.finditer(unit.source):
            email_address = email_match.group(0)
            # Git SSH references contain an email-shaped user/host prefix, not a person's address.
            if _is_scp_style_git_reference(unit.source, email_match.end(), email_address):
                continue
            # Reserved domains are safe fixture placeholders rather than third-party PII.
            if _is_placeholder_email_domain(email_match.group("domain")):
                continue
            findings.append(_build_pii_finding(definition, unit, email_match.start(), "email"))
        # Phone candidates need a plausible shape or an explicit nearby phone label.
        for phone_match in _PHONE_RE.finditer(unit.source):
            # Known placeholders and numeric fixtures do not identify a person.
            if (
                phone_match.group("area") in _PLACEHOLDER_PHONE_SEGMENTS
                or phone_match.group("exchange") in _PLACEHOLDER_PHONE_SEGMENTS
                or _is_known_non_phone_number(unit.source, phone_match)
            ):
                continue
            findings.append(_build_pii_finding(definition, unit, phone_match.start(), "phone"))
        return findings


def _is_test_fixture_path(display_path: str) -> bool:
    """Return whether a path follows a recognised test or fixture convention.

    Args:
        display_path: Report path to classify; an empty path has no test/fixture convention.

    Returns:
        True for recognised directory segments or filenames; false for incidental substrings in
        parent paths.
    """
    normalised_path = display_path.replace("\\", "/").lower()
    path_parts = normalised_path.split("/")
    filename = path_parts[-1]
    filename_stem = filename.rsplit(".", 1)[0]
    directory_names = frozenset(path_parts[:-1])
    return (
        bool(directory_names & _TEST_FIXTURE_DIRECTORY_NAMES)
        or any(_is_test_fixture_directory_name(name) for name in directory_names)
        or filename_stem in {"conftest", "fixture", "fixtures", "test", "tests"}
        or filename_stem.startswith(("fixture_", "test_"))
        or filename_stem.endswith(("_fixture", "_test"))
    )


def _is_test_fixture_directory_name(directory_name: str) -> bool:
    """Return whether a compound directory names a test or fixture collection.

    The final token includes ``integration_tests`` and ``test-fixtures`` while keeping an incidental
    qualifier such as ``test-scan-repos`` outside the user's fixture findings.

    Args:
        directory_name: One lowercase path segment; empty text names nothing.

    Returns:
        True when the segment's last token is a test or fixture word.
    """
    last_token = re.split(r"[-_.]", directory_name)[-1]
    return last_token in _TEST_FIXTURE_DIRECTORY_SUFFIX_TOKENS


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


def _is_known_non_phone_number(source: str, match: re.Match[str]) -> bool:
    """Return whether a bare digit sequence is a known non-phone fixture shape.

    Args:
        source: Full fixture text containing the candidate.
        match: Phone-shaped regex match; separator-bearing matches are already phone-like.

    Returns:
        True for decimal fragments, timestamps, and sequential digit fixtures; false for other
        bare or formatted values.
    """
    raw = match.group(0)
    # Formatted values retain the security signal unless an existing placeholder rule handles them.
    if not raw.isdigit():
        return False
    # A matched slice inside a decimal metric is numeric data, not a contact number.
    if _is_decimal_number_fragment(source, match):
        return True
    context = _source_context_for_match(source, match)
    # Timestamp labels explain bare digits without weakening other unformatted phone findings.
    if any(term in context for term in _TIMESTAMP_CONTEXT_TERMS):
        return True
    # These measured charset/test-string values are deterministic sequences, not contact numbers.
    return raw in _SEQUENTIAL_DIGIT_FIXTURES


def _is_decimal_number_fragment(source: str, match: re.Match[str]) -> bool:
    """Return whether a phone-shaped match is part of decimal data a user need not replace."""
    before = source[match.start() - 1] if match.start() > 0 else ""
    after = source[match.end()] if match.end() < len(source) else ""
    after_next = source[match.end() + 1] if match.end() + 1 < len(source) else ""
    return before == "." or (after == "." and after_next.isdigit())


def _source_context_for_match(source: str, match: re.Match[str]) -> str:
    """Return nearby lowercase text used to recognize labelled timestamp fixtures."""
    line_start = _context_line_start(source, match.start(), previous_lines=2)
    line_end = source.find("\n", match.end())
    # A final line without a newline still contributes its full context to fixture classification.
    if line_end == -1:
        line_end = len(source)
    window_start = max(0, match.start() - 40)
    window_end = min(len(source), match.end() + 40)
    return f"{source[line_start:line_end]} {source[window_start:window_end]}".lower()


def _context_line_start(source: str, offset: int, previous_lines: int) -> int:
    """Return the start offset that provides enough prior user context for classification."""
    start = source.rfind("\n", 0, offset)
    # Nearby prior lines may contain the label that explains an otherwise phone-shaped number.
    for _ in range(previous_lines):
        # Reaching the file start means no earlier context is available for this user value.
        if start <= 0:
            return 0
        start = source.rfind("\n", 0, start)
    return start + 1


def _build_pii_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    offset: int,
    kind: str,
) -> Finding:
    """Build the fixed-preview PII finding shown at the matched fixture line."""
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
            "Replace with documented placeholders (`user@example.com`, `user@app.test`, `+1-555-...`) so test failures don't expose third-party PII."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"preview": category_preview(kind), "kind": kind},
    )
