"""``security.insecure-tls-protocol`` - explicit downgrade to SSLv2/v3 or TLSv1/1.1.

Matches ``ssl.<protocol>`` attribute references where the protocol is one of
the deprecated constants (``PROTOCOL_SSLv2``, ``PROTOCOL_SSLv3``,
``PROTOCOL_TLSv1``, ``PROTOCOL_TLSv1_1``, ``PROTOCOL_SSLv23``). These constants
exist only to be passed to SSL context constructors; their appearance in
source is always an explicit protocol choice.

``ssl._create_unverified_context()`` is covered by
``security.disabled-ssl-verification`` and intentionally not duplicated here.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_metadata import finding_security_metadata

_INSECURE_PROTOCOL_ATTRS: frozenset[str] = frozenset(
    {
        "PROTOCOL_TLSv1",
        "PROTOCOL_TLSv1_1",
        "PROTOCOL_SSLv2",
        "PROTOCOL_SSLv3",
        "PROTOCOL_SSLv23",
    }
)
_SOURCE_NEEDLES: tuple[str, ...] = (
    "PROTOCOL_TLSv1",
    "PROTOCOL_SSLv2",
    "PROTOCOL_SSLv3",
    "PROTOCOL_SSLv23",
)
_REMEDIATION = (
    "Use a modern TLS protocol - prefer `ssl.PROTOCOL_TLS_CLIENT` or "
    "`ssl.PROTOCOL_TLS_SERVER`, or `ssl.PROTOCOL_TLSv1_2` if a specific "
    "version is required. SSLv2, SSLv3, TLSv1, and TLSv1.1 have known "
    "vulnerabilities and are deprecated."
)


class InsecureTlsProtocolRule(Rule):
    """Detect references to deprecated SSL/TLS protocol constants on the `ssl` module."""

    ID = "security.insecure-tls-protocol"

    def definition(self) -> RuleDefinition:
        """Describe the insecure-TLS-protocol rule as a high-confidence ERROR.

        ERROR severity because SSLv2/v3 and TLSv1/v1.1 are known-broken
        protocols; high confidence because the matched attribute names are
        unambiguous - they exist only to be passed to SSL context
        constructors.

        Returns:
            Definition for the insecure-TLS-protocol rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Insecure TLS protocol",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``ssl.PROTOCOL_<weak>`` attribute references.

        The rule matches the ``ssl.<weak-protocol>`` attribute shape
        anywhere it appears (assignment, argument, return). The
        ``from ssl import PROTOCOL_TLSv1`` shape followed by a bare-name
        reference is intentionally not matched - that import shape is rare
        and the false-positive cost of bare-name reuse would dominate.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per insecure-protocol attribute reference.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr not in _INSECURE_PROTOCOL_ATTRS:
                continue
            if not isinstance(node.value, ast.Name) or node.value.id != "ssl":
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.Attribute,
) -> Finding:
    target = f"ssl.{node.attr}"
    return Finding(
        rule_id=definition.id,
        message=f"`{target}` is a deprecated SSL/TLS protocol with known vulnerabilities.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "target": target,
            **finding_security_metadata(
                definition.id,
                source_label="tls-protocol-constant",
                sink_label="tls-handshake",
            ),
        },
    )
