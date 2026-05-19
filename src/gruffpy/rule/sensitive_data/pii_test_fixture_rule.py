"""``sensitive-data.pii-test-fixture`` — realistic PII in test fixtures.

Fires on emails / phone numbers / addresses that look real (not placeholder
domains, not ``555`` US-test prefixes). Scoped to test paths so production
config containing the same patterns isn't surfaced.
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
# 555 in the exchange position (NXX-555-NNNN) is the canonical US placeholder
# for fictitious numbers. The area-code 555 is also reserved for directory-
# assistance use, so treat either position as a placeholder.
_PLACEHOLDER_PHONE_SEGMENTS: frozenset[str] = frozenset({"555"})


class PiiTestFixtureRule(SourceTextRule):
    """Detect realistic emails or phone numbers in test/fixture files (ignoring placeholders)."""

    ID = "sensitive-data.pii-test-fixture"

    def definition(self) -> RuleDefinition:
        """Describe the PII-in-test-fixture rule as a medium-confidence warning.

        Medium confidence because realistic-looking emails/phones don't
        always belong to a real person; the placeholder allowlists
        (``example.com``, ``555`` numbers) cover the canonical fixture
        shapes.

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
        Placeholder domains (``example.com``, ``test.com``, ``localhost``,
        etc.) and US ``555`` area / exchange codes are recognised and
        skipped.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per realistic email or phone in a test/fixture file.
        """
        if not _is_test_path(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _EMAIL_RE.finditer(unit.source):
            if match.group("domain").lower() in _PLACEHOLDER_DOMAINS:
                continue
            findings.append(
                _build_finding(definition, unit, match.start(), match.group(0), "email")
            )
        for match in _PHONE_RE.finditer(unit.source):
            if (
                match.group("area") in _PLACEHOLDER_PHONE_SEGMENTS
                or match.group("exchange") in _PLACEHOLDER_PHONE_SEGMENTS
            ):
                continue
            findings.append(
                _build_finding(definition, unit, match.start(), match.group(0), "phone")
            )
        return findings


def _is_test_path(display_path: str) -> bool:
    return "test" in display_path.lower() or "fixture" in display_path.lower()


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
            "Replace with documented placeholders (`user@example.com`, `+1-555-...`) "
            "so test failures don't expose third-party PII."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"preview": redact_preview(value), "kind": kind},
    )
