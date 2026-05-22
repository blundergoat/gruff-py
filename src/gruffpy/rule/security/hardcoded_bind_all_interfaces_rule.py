"""``security.hardcoded-bind-all-interfaces`` — server bound to 0.0.0.0 / ::.

Binding to ``0.0.0.0`` (IPv4 wildcard) or ``::`` (IPv6 wildcard) exposes a
server on every network interface. Inside a container or behind a reverse
proxy this is sometimes deliberate; in application code it is almost always
a mistake — the developer wanted ``127.0.0.1`` for local-only access.

Match shapes (no framework gate — the address literal is unambiguous):

- ``<server>.run(..., host="0.0.0.0", ...)`` — Flask, Quart, uvicorn,
  hypercorn, gunicorn-style apps
- ``socket.bind(("0.0.0.0", port))`` — stdlib socket
- Also fires on ``"::"`` IPv6 wildcard

The rule emits at ``warning`` severity because containerised deploys and
intentional public bind targets are legitimate; the finding's role is to
make the choice explicit during review.
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
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name

_WILDCARD_ADDRESSES: frozenset[str] = frozenset({"0.0.0.0", "::"})
_SOURCE_NEEDLES: tuple[str, ...] = ("0.0.0.0", '"::"', "'::'")
_REMEDIATION = (
    "Bind to `127.0.0.1` (or `::1`) when the server should only accept "
    "local traffic. If a public bind is intentional (containerised deploy, "
    "reverse-proxy backend), document it in a comment or move the literal "
    "into configuration so the choice is auditable."
)


class HardcodedBindAllInterfacesRule(Rule):
    """Detect servers bound to the IPv4/IPv6 wildcard address."""

    ID = "security.hardcoded-bind-all-interfaces"

    def definition(self) -> RuleDefinition:
        """Describe the wildcard-bind rule as a medium-confidence WARNING.

        WARNING severity because the address is intentional in many
        legitimate deploys (containers, reverse-proxy backends); medium
        confidence because the string literal is unambiguous but the
        deployment context that makes it acceptable is invisible to the
        analyser.

        Returns:
            Definition for the wildcard-bind rule under the security
            pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Hardcoded bind to all interfaces",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``host=`` kwargs and ``socket.bind`` first-args holding wildcard literals.

        No framework gate — the wildcard address literal is unambiguous
        enough to stand alone. Fires once per call site, not once per
        wildcard occurrence inside a call (so ``run(host='0.0.0.0',
        debug=False)`` is one finding, not two).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per wildcard-bind call site.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            address = _wildcard_bind_address(node)
            if address is None:
                continue
            findings.append(_build_finding(definition, unit, node, address))
        return findings


def _wildcard_bind_address(call: ast.Call) -> str | None:
    if _is_run_call_with_wildcard_host(call):
        host = call_keyword(call, "host")
        return _string_literal_value(host)
    if _is_socket_bind_call(call) and call.args:
        return _wildcard_from_bind_tuple(call.args[0])
    return None


def _is_run_call_with_wildcard_host(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "run":
        return False
    host = call_keyword(call, "host")
    if host is None:
        return False
    value = _string_literal_value(host)
    return value in _WILDCARD_ADDRESSES


def _is_socket_bind_call(call: ast.Call) -> bool:
    if not isinstance(call.func, ast.Attribute) or call.func.attr != "bind":
        return False
    target = call_target_name(call)
    if target is None:
        return True
    return "socket" in target.split(".") or target.endswith(".bind")


def _wildcard_from_bind_tuple(arg: ast.expr) -> str | None:
    if not isinstance(arg, ast.Tuple) or not arg.elts:
        return None
    address = _string_literal_value(arg.elts[0])
    if address in _WILDCARD_ADDRESSES:
        return address
    return None


def _string_literal_value(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    address: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Server binding to wildcard address `{address}` — exposes the "
            "service on every network interface."
        ),
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "address": address,
            **finding_security_metadata(
                definition.id,
                source_label="network-listener",
                sink_label="bind-address",
            ),
        },
    )
