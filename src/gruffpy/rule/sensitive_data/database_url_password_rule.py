"""``sensitive-data.database-url-password`` — credentialled DB connection URL.

Pattern: ``<scheme>://<user>:<password>@<host>`` where the password is not a
placeholder (``password``, ``changeme``, ``xxx``, ``***``, blank). Covers
Postgres, MySQL, MariaDB, MongoDB, Redis, ClickHouse, and the most common
SQLAlchemy-style URLs.
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
    iter_matches,
    redact_preview,
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
        "password",
        "PASSWORD",
        "changeme",
        "CHANGEME",
        "xxx",
        "XXX",
        "***",
        "your_password",
        "<password>",
    }
)


class DatabaseUrlPasswordRule(SourceTextRule):
    """Detect database connection URLs that embed a non-placeholder password in the userinfo."""

    ID = "sensitive-data.database-url-password"

    def definition(self) -> RuleDefinition:
        """Describe the database-URL-password rule as a high-confidence ERROR.

        ERROR severity because a credentialled connection string in source
        usually unlocks the whole database surface; the supported scheme
        list (Postgres, MySQL, Mongo, Redis, ClickHouse, AMQP, ...) is wide
        but exact.

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

        Common placeholders (``password``, ``changeme``, ``xxx``, ``***``,
        ``<password>``, etc.) are recognised and skipped so example
        connection strings in docs and tests don't fire.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per database URL whose password is not a placeholder.
        """
        definition = self.definition()
        findings: list[Finding] = []
        for match in iter_matches(_PATTERN, unit.source):
            password = _extract_password(match.raw)
            if password is None or password in _PLACEHOLDER_PASSWORDS:
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Database URL with embedded credential.",
                    file_path=unit.file.display_path,
                    line=match.line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Move the password out of the connection string. Use environment "
                        "variables or a secret manager and assemble the URL at runtime."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"preview": redact_preview(password)},
                ),
            )
        return findings


def _extract_password(url: str) -> str | None:
    """Return the password segment of a ``scheme://user:password@host`` URL."""
    scheme_split = url.split("://", 1)
    if len(scheme_split) != 2:
        return None
    after_scheme = scheme_split[1]
    at_split = after_scheme.split("@", 1)
    if len(at_split) != 2:
        return None
    user_password = at_split[0]
    colon_split = user_password.split(":", 1)
    if len(colon_split) != 2:
        return None
    return colon_split[1]
