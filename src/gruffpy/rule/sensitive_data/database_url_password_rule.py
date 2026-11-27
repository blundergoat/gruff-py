"""Check database connection URLs for embedded passwords under `sensitive-data.database-url-password`.

The rule covers common database and SQLAlchemy-style schemes.
Placeholders and stock local development pairs are skipped so the review focuses on real-looking credentials.
A finding points to the URL location without showing the password.
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
    compile_pattern,
    connection_string_preview,
    iter_matches,
)

_SCHEMES = (
    "postgres",
    "postgresql",
    "postgresql\\+psycopg",
    "postgresql\\+psycopg2",
    "postgresql\\+asyncpg",
    "mysql",
    "mysql\\+pymysql",
    "mariadb",
    "mongodb",
    "mongodb\\+srv",
    "redis",
    "rediss",
    "clickhouse",
    "amqp",
    "amqps",
)
_PATTERN = compile_pattern(rf"(?:{'|'.join(_SCHEMES)})://[A-Za-z0-9_-]+:([^@\s/]+)@[A-Za-z0-9.-]+")
_PLACEHOLDER_PASSWORDS: frozenset[str] = frozenset(
    {
        "",
        "password",
        "changeme",
        "change-me",
        "xxx",
        "***",
        "****",
        "your_password",
        "<password>",
        "dummy",
        "fake",
        "redacted",
    }
)
# Stock development user names and passwords, compared case-insensitively and whole (FAMILY-CONTRACT.md section 5).
# They are documented defaults such as ``scott:tiger``, not credentials, so they are held as plain text.
_STOCK_DEVELOPMENT_WORDS: frozenset[str] = frozenset(
    {
        "admin", "bar", "dbpass", "dbuser", "default", "demo", "example", "foo", "guest", "mysql", "pass",
        "passwd", "password", "postgres", "root", "sa", "scott", "secret", "test", "tiger", "user", "username",
    }
)  # fmt: skip
# Loopback hosts, on which a stock pair is a development default rather than a live weakness.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})


class DatabaseUrlPasswordRule(SourceTextRule):
    """Detect database URLs that embed a non-placeholder password.

    Users see this rule after committing a URL such as ``postgres://user:<password>@db`` and can
    move the password to runtime configuration without its characters appearing in output.
    """

    ID = "sensitive-data.database-url-password"

    def definition(self) -> RuleDefinition:
        """Describe the database-URL-password rule as a high-confidence warning.

        Exact supported schemes give users high-confidence findings, while warning severity reflects
        the broad access an exposed database credential can provide.

        Returns:
            Definition for the database-URL-password rule under the
            sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Database URL with password",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Report database URLs that carry a literal password in the selected source.
        A source location leads the reviewer to the setting to fix. The finding shows a redacted preview.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per matched URL that survives password parsing, placeholder checks and stock development exclusions.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Several connection settings can appear on one line. Each real password needs its own finding.
        for database_url_match in iter_matches(_PATTERN, unit.source):
            embedded_password = _extract_password(database_url_match.raw)
            # URLs with no password, a template value or stock local credentials do not merit a credential finding.
            if embedded_password is None or _is_placeholder_password(embedded_password) or _is_stock_development_url(database_url_match.raw):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Database URL with embedded credential.",
                    file_path=unit.file.display_path,
                    line=database_url_match.line,
                    column=database_url_match.column,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Move the password out of the connection string. Use environment "
                        "variables or a secret manager and assemble the URL at runtime."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": connection_string_preview(_extract_scheme(database_url_match.raw))},
                ),
            )
        return findings


def _extract_scheme(url: str) -> str:
    """Return the scheme of a ``scheme://user:password@host`` URL.

    Only the scheme is retained in connection-string markers; credentials and host details stay out of previews.

    Args:
        url: Matched URL text; one of the schemes this rule's own pattern accepts.

    Returns:
        The scheme, or an empty string when the URL carries no scheme boundary.
    """
    scheme, separator, _ = url.partition("://")
    # A URL without a scheme boundary cannot have been matched by this rule's pattern.
    return scheme if separator else ""


def _extract_password(url: str) -> str | None:
    """Return the password segment of a ``scheme://user:password@host`` URL.

    Args:
        url: Candidate connection text; extraction inspects its separator positions without validating the scheme or host.

    Returns:
        Password text before the first host separator, without decoding. None when a scheme, host or password separator is missing; an empty string
        when the password segment is empty.
    """
    scheme_parts = url.split("://", 1)
    # A URL without a scheme boundary cannot provide a reliable credential location to the user.
    if len(scheme_parts) != 2:
        return None
    url_authority = scheme_parts[1]
    authority_parts = url_authority.split("@", 1)
    # Without a host separator, the candidate is not an embedded URL credential.
    if len(authority_parts) != 2:
        return None
    user_credentials = authority_parts[0]
    credential_parts = user_credentials.split(":", 1)
    # Without a password separator, there is nothing sensitive to report to the user.
    if len(credential_parts) != 2:
        return None
    return credential_parts[1]


def _is_placeholder_password(password: str) -> bool:
    """Return whether the password is an exact known fixture placeholder.

    Args:
        password: Extracted password to compare after stripping surrounding whitespace and folding case.

    Returns:
        True for empty or whitespace-only passwords and values that normalize to a listed placeholder. False otherwise.
    """
    return password.strip().casefold() in _PLACEHOLDER_PASSWORDS


def _is_stock_development_url(url: str) -> bool:
    """Return whether a matched URL holds a stock development pair on a loopback or single-label host.

    The same pair on any other host still reports, because a default credential on a reachable host is a
    live weakness (FAMILY-CONTRACT.md section 5).

    Args:
        url: Matched ``scheme://user:password@host`` text; the rule's pattern stops the host before any port.

    Returns:
        True when the user name and the password are both stock words and the host is ``localhost``,
        ``127.0.0.1``, ``::1``, ``0.0.0.0`` or a name with no dot, such as a Compose service called ``db``.
    """
    _, _, authority = url.partition("://")
    credentials, _, host = authority.partition("@")
    user, _, password = credentials.partition(":")
    # Both halves must be stock words; one real word keeps the finding.
    if user.casefold() not in _STOCK_DEVELOPMENT_WORDS or password.casefold() not in _STOCK_DEVELOPMENT_WORDS:
        return False
    host = host.casefold()
    return host in _LOOPBACK_HOSTS or (host != "" and "." not in host)
