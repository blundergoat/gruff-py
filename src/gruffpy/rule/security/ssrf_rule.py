"""``security.ssrf`` — HTTP client calls reached by user-controlled URLs.

Server-Side Request Forgery: an attacker who can influence the URL passed
to an outbound HTTP client can pivot the server into making requests to
internal services, cloud metadata endpoints, or other targets the client
can reach but the attacker cannot.

The rule uses the bounded intra-procedural taint helper
(``_security_taint_helper.py``) per ADR-017. A finding fires when the URL
argument of a known HTTP-client sink is tainted by a recognised request
source in the same function.

Recognised sinks (gated by ``requests`` / ``httpx`` / ``urllib`` / ``urllib3``
import):

- ``requests.get/post/put/patch/delete/head/options(<url>, ...)`` —
  first argument is the URL.
- ``requests.request("GET", <url>, ...)`` — second argument is the URL.
- ``httpx.get/post/put/patch/delete/head/options(<url>, ...)`` — same.
- ``httpx.request("GET", <url>, ...)`` — second argument.
- ``urlopen(<url>, ...)`` (from ``urllib.request``) — first argument.

Aliased imports (``import requests as r``, chained
``requests.Session().get(...)`` shapes) are out of scope for v1 — they
require import-graph or symbolic-receiver tracking.
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
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.security._security_taint_helper import TaintAnalyser

_HTTP_CLIENT_MODULES: frozenset[str] = frozenset({"requests", "httpx", "urllib", "urllib3"})
_HTTP_VERB_LEAVES: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options"}
)
_REQUEST_METHOD_LEAVES: frozenset[str] = frozenset({"request"})
_URLOPEN_LEAVES: frozenset[str] = frozenset({"urlopen"})
_SSRF_SANITISERS: frozenset[str] = frozenset()
_SOURCE_NEEDLES: tuple[str, ...] = ("request", "urlopen", "httpx")
_REMEDIATION = (
    "Validate the URL against an explicit allow-list of hosts (or whole "
    "URLs) before passing it to the client. Reject URLs that resolve to "
    "private / link-local / loopback addresses if external-only fetches "
    "are required. `urllib.parse.urlparse(...).netloc` returns a string "
    "the developer still has to compare against an allow-list — calling "
    "it alone is not a sanitiser."
)


class SsrfRule(Rule):
    """Detect HTTP-client calls whose URL is tainted by a user-controlled source."""

    ID = "security.ssrf"

    def definition(self) -> RuleDefinition:
        """Describe the SSRF rule as a high-confidence ERROR.

        ERROR severity because SSRF is a frequent pivot for AWS metadata
        exfiltration and internal-network probing; high confidence because
        the matched sinks + intra-procedural taint reach the URL argument
        without ambiguity.

        Returns:
            Definition for the SSRF rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Server-side request forgery (SSRF)",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag HTTP-client sinks reached by tainted URL arguments.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per call site whose URL argument is tainted.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        if not _has_http_client_import(unit.tree):
            return []
        taint_map = TaintAnalyser(_SSRF_SANITISERS).analyse_tree(unit.tree)
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            url_arg = _ssrf_url_argument(node)
            if url_arg is None or not taint_map.is_tainted(url_arg):
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


def _has_http_client_import(tree: ast.AST) -> bool:
    if not isinstance(tree, ast.Module):
        return False
    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _HTTP_CLIENT_MODULES:
                    return True
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            root = node.module.split(".")[0]
            if root in _HTTP_CLIENT_MODULES:
                return True
    return False


def _ssrf_url_argument(call: ast.Call) -> ast.expr | None:
    target = call_target_name(call)
    if target is None:
        return None
    leaf = target.split(".")[-1]
    if leaf in _HTTP_VERB_LEAVES and call.args:
        return call.args[0]
    if leaf in _REQUEST_METHOD_LEAVES and len(call.args) >= 2:
        return call.args[1]
    if leaf in _URLOPEN_LEAVES and call.args:
        return call.args[0]
    return None


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    target = call_target_name(call) or "?"
    return Finding(
        rule_id=definition.id,
        message=(
            f"`{target}(...)` receives a user-controlled URL — SSRF risk via "
            "internal services, cloud metadata, or other reachable targets."
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
            "target": target,
            **finding_security_metadata(
                definition.id,
                source_label="user-controlled-url",
                sink_label="http-client",
            ),
        },
    )
