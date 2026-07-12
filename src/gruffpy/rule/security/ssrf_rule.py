"""Report user-controlled URLs passed to direct, supported HTTP clients.

Users see this finding when request data reaches a documented outbound call.
Supported calls are ``requests``/``httpx`` verbs and their ``request`` methods,
plus ``urllib.request.urlopen`` and directly imported bare ``urlopen``.
URLs may be positional or use ``url=``. Aliases, client instances, wrappers,
and ``urllib3`` stay quiet; ADR-017 keeps taint within the current function.
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
from gruffpy.rule.security._security_taint_helper import TaintAnalyser

_HTTP_VERB_TARGETS: frozenset[str] = frozenset(
    {
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.options",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "httpx.head",
        "httpx.options",
    }
)
_REQUEST_METHOD_TARGETS: frozenset[str] = frozenset({"requests.request", "httpx.request"})
_QUALIFIED_URLOPEN_TARGET = "urllib.request.urlopen"
_SSRF_SANITISERS: frozenset[str] = frozenset()
_SOURCE_NEEDLES: tuple[str, ...] = ("request", "urlopen", "httpx")
_REMEDIATION = (
    "Validate the URL against an explicit allow-list of hosts (or whole "
    "URLs) before passing it to the client. Reject URLs that resolve to "
    "private / link-local / loopback addresses if external-only fetches "
    "are required. `urllib.parse.urlparse(...).netloc` returns a string "
    "the developer still has to compare against an allow-list - calling "
    "it alone is not a sanitiser."
)


class SsrfRule(Rule):
    """Turn tainted, supported HTTP calls into user-facing SSRF findings.

    The scanner uses exact call targets to avoid blaming application-owned
    ``get`` or ``request`` methods while retaining the documented client matrix.
    """

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
        """Show SSRF findings for supported calls reached by request data.

        Args:
            unit: Parsed user source; no tree means the file could not be inspected.
            context: Rule execution context (unused - no thresholds).

        Returns:
            Findings visible to the user, or an empty list when no supported sink is unsafe.
        """
        # A parse failure or missing client token gives the user no reliable SSRF judgment.
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        direct_urlopen_is_imported = _has_direct_urlopen_import(unit.tree)
        taint_map = TaintAnalyser(_SSRF_SANITISERS).analyse_tree(unit.tree)
        definition = self.definition()
        findings: list[Finding] = []
        # Each parsed call is checked against the small matrix shown in rule documentation.
        for node in ast.walk(unit.tree):
            # Non-call syntax cannot send a URL, so it never becomes a user finding.
            if not isinstance(node, ast.Call):
                continue
            user_url = _supported_http_client_url_argument(
                node,
                direct_urlopen_is_imported=direct_urlopen_is_imported,
            )
            # Unsupported calls and fixed URLs stay out of the user's result list.
            if user_url is None or not taint_map.is_tainted(user_url):
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


def _has_direct_urlopen_import(tree: ast.AST) -> bool:
    """Return whether the user imported bare ``urlopen`` without an alias.

    Args:
        tree: Parsed module containing the user's imports.

    Returns:
        True only for ``from urllib.request import urlopen`` at module scope.
    """
    # Only a module can expose a direct import to the calls analysed below.
    if not isinstance(tree, ast.Module):
        return False
    # Module-level imports are the only direct binding this rule promises to resolve.
    for statement in tree.body:
        # Ordinary imports and user statements cannot bind a bare ``urlopen`` here.
        if not isinstance(statement, ast.ImportFrom):
            continue
        # Other ``from`` imports do not authorize a bare URL-opening sink.
        if statement.module != "urllib.request":
            continue
        # Aliased imports remain out of scope so the displayed matrix stays exact.
        for imported_name in statement.names:
            # The plain binding is safe to identify without import-graph or object flow.
            if imported_name.name == "urlopen" and imported_name.asname is None:
                return True
    return False


def _supported_http_client_url_argument(
    call: ast.Call,
    *,
    direct_urlopen_is_imported: bool,
) -> ast.expr | None:
    """Return the URL expression for a documented direct HTTP-client call.

    Args:
        call: User call expression being checked as a possible sink.
        direct_urlopen_is_imported: Whether bare ``urlopen`` has its supported import.

    Returns:
        Positional or ``url=`` expression, or None for unsupported/missing URL shapes.
    """
    target = call_target_name(call)
    # Dynamic callees cannot be tied to a documented client in the UI.
    if target is None:
        return None
    # Direct verbs take their URL first, or from the explicit ``url=`` keyword.
    if target in _HTTP_VERB_TARGETS:
        return _positional_or_keyword_url(call, positional_index=0)
    # Generic request methods take method first and URL second, or use ``url=``.
    if target in _REQUEST_METHOD_TARGETS:
        return _positional_or_keyword_url(call, positional_index=1)
    # The fully qualified standard-library call is unambiguous without import tracking.
    if target == _QUALIFIED_URLOPEN_TARGET:
        return _positional_or_keyword_url(call, positional_index=0)
    # A bare name is supported only when the user imported it directly without an alias.
    if target == "urlopen" and direct_urlopen_is_imported:
        return _positional_or_keyword_url(call, positional_index=0)
    return None


def _positional_or_keyword_url(call: ast.Call, *, positional_index: int) -> ast.expr | None:
    """Return a supported positional URL before falling back to ``url=``.

    Args:
        call: Supported HTTP-client call from the user's source.
        positional_index: Argument slot used by that client method.

    Returns:
        URL expression, or None when the user supplied no supported URL argument.
    """
    # Positional URLs are the client's primary public calling form.
    if len(call.args) > positional_index:
        return call.args[positional_index]
    return call_keyword(call, "url")


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
) -> Finding:
    """Build the SSRF result shown to a user for one unsafe HTTP call.

    Args:
        definition: Stable rule classification used by reports and scoring.
        unit: User source file containing the unsafe call.
        call: Supported HTTP call whose URL is tainted.

    Returns:
        Finding with unchanged remediation and security metadata.
    """
    target = call_target_name(call) or "?"
    return Finding(
        rule_id=definition.id,
        message=(
            f"`{target}(...)` receives a user-controlled URL - SSRF risk via "
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
