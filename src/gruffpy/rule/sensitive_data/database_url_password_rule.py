"""``sensitive-data.database-url-password`` - credentialled DB connection URL.

Pattern: ``<scheme>://<user>:<password>@<host>`` where the password is not a
placeholder (``password``, ``changeme``, ``change-me``, ``xxx``, ``***``,
``****``, ``dummy``, ``fake``, ``redacted``, blank). Covers Postgres, MySQL,
MariaDB, MongoDB, Redis, ClickHouse, and the most common SQLAlchemy-style URLs.
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


class DatabaseUrlPasswordRule(SourceTextRule):
    """Detect database URLs that embed a non-placeholder password.

    Users see this rule after committing a URL such as ``postgres://user:<password>@db`` and can
    move the password to runtime configuration without its characters appearing in output.
    """

    ID = "sensitive-data.database-url-password"

    def definition(self) -> RuleDefinition:
        """Describe the database-URL-password rule as a high-confidence ERROR.

        Exact supported schemes give users high-confidence findings, while error severity reflects
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
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan raw source for ``<scheme>://user:password@host`` URLs with a real password.

        Users see each credential-bearing URL, while common placeholder passwords in examples and
        tests remain quiet.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per database URL whose password is not a placeholder.
        """
        definition = self.definition()
        findings: list[Finding] = []
        # Each credential-bearing URL becomes a separate item in the user's remediation queue.
        for database_url_match in iter_matches(_PATTERN, unit.source):
            embedded_password = _extract_password(database_url_match.raw)
            # Unparseable or placeholder passwords do not represent a credential the user must
            # rotate.
            if embedded_password is None or _is_placeholder_password(embedded_password):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Database URL with embedded credential.",
                    file_path=unit.file.display_path,
                    line=database_url_match.line,
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

    The scheme is the only part of a connection string the URL already publishes in plain text, so it
    is the only part a marker may name.

    Args:
        url: Matched URL text; one of the schemes this rule's own pattern accepts.

    Returns:
        The scheme, or an empty string when the URL carries no scheme boundary.
    """
    scheme, separator, _ = url.partition("://")
    # A URL without a scheme boundary cannot have been matched by this rule's pattern.
    return scheme if separator else ""


def _extract_password(url: str) -> str | None:
    """Return the password segment of a ``scheme://user:password@host`` URL."""
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
    """Return whether *password* is an exact known fixture placeholder."""
    return password.strip().casefold() in _PLACEHOLDER_PASSWORDS
