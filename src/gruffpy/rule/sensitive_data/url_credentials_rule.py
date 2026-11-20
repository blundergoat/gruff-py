"""``sensitive-data.url-credentials`` - HTTP(S) URL with embedded credentials.

Detects ``http(s)://user:password@host`` URL literals. Database schemes remain
owned by ``sensitive-data.database-url-password`` so the two rules do not
duplicate the same finding. A captured password holding template syntax or
characters that show the capture ran past the userinfo is not a credential, and
the same URL repeated on the next line is reported once.
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
    compile_pattern,
    connection_string_preview,
    is_likely_placeholder_secret,
    iter_matches,
)

_PATTERN = compile_pattern(
    r"\bhttps?://(?P<user>[^:\s/@]+):(?P<password>[^@\s\"']+)@(?P<host>[^\s\"']+)",
    ignore_case=True,
)
# Braces are template placeholders; a backslash, a slash, or a second colon means the capture ran past the userinfo.
_NON_CREDENTIAL_CHARACTERS: frozenset[str] = frozenset("{}\\/:")
# A percent sign that does not open a two-digit escape is a printf-style placeholder, while ``%40`` stays a real
# percent-encoded character of a password that must still be reported.
_TEMPLATE_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class UrlCredentialsRule(SourceTextRule):
    """Detect HTTP(S) URLs that embed username and password credentials.

    Users see a finding after placing ``user:password@host`` in source and can move authentication
    to headers or runtime settings without the URL or password appearing in the preview.
    """

    ID = "sensitive-data.url-credentials"

    def definition(self) -> RuleDefinition:
        """Describe the URL-credentials rule as a high-confidence warning.

        Returns:
            Definition for the URL-credentials rule under the sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="URL embedded credentials",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            # Off unless a project enables it: wrong on all 3 judged findings in the 0.6.0 measurement; too few to delete on (ADR-029).
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan raw source for HTTP(S) URLs with inline ``user:password@`` credentials.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            Findings for passwords accepted by extraction and the placeholder filter, with a redacted preview.
            A match is skipped if the preceding eligible match was the same URL on the previous line. Empty if no URL qualifies.
        """
        definition = self.definition()
        findings: list[Finding] = []
        previous_report: tuple[int, str] | None = None
        for credential_match in iter_matches(_PATTERN, unit.source):
            embedded_password = _extract_password(credential_match.raw)
            # Template-like segments and likely placeholders are excluded to avoid reporting URL construction examples.
            if embedded_password is None or is_likely_placeholder_secret(embedded_password):
                continue
            repeats_previous_line = previous_report == (credential_match.line - 1, credential_match.raw)
            previous_report = (credential_match.line, credential_match.raw)
            # An intervening eligible URL can keep repeats on consecutive lines from sharing a finding.
            if repeats_previous_line:
                continue
            # This rule's pattern matches only http and https, and the matched text starts with whichever it was.
            redacted_marker = connection_string_preview(credential_match.raw.split("://", 1)[0])
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"HTTP(S) URL embeds an inline credential: {redacted_marker}.",
                    file_path=unit.file.display_path,
                    line=credential_match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=("Remove inline URL credentials; pass authentication via headers, environment variables, or a secret store instead."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redacted_marker, "category": "url-credentials"},
                ),
            )
        return findings


def _extract_password(url: str) -> str | None:
    """Return the password segment from an HTTP(S) URL userinfo block.

    Args:
        url: Matched credential-bearing URL text.

    Returns:
        The captured password as written, or None if there is no password separator or the segment contains a brace, backslash, slash, colon,
        or a percent sign without two following hexadecimal digits.
    """
    before_host = url.split("@", 1)[0]
    userinfo = before_host.split("://", 1)[-1]
    credential_parts = userinfo.split(":", 1)
    # A username alone does not trigger this password check.
    if len(credential_parts) != 2:
        return None
    password = credential_parts[1]
    # Treat these characters as signs of templating or a capture that crossed a URL component boundary.
    if any(character in _NON_CREDENTIAL_CHARACTERS for character in password) or _TEMPLATE_PERCENT.search(password):
        return None
    return password
