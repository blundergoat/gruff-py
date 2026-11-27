"""Report user-controlled URLs passed to direct, supported HTTP clients.

Users see this finding when request data reaches a documented outbound call.
Supported calls are ``requests``/``httpx`` verbs and their ``request`` methods,
plus ``urllib.request.urlopen`` and directly imported bare ``urlopen``.
Each receiver requires an exact same-unit import binding that is live when the
call executes. Function-local names bind retroactively; module, class, and
member stores resolve to the last one in source order, so a canonical import
after an earlier shadow still proves the client. URLs may be positional or
use ``url=``.
Aliases, client instances, wrappers, and ``urllib3`` stay quiet; ADR-017
keeps taint within the current function.
"""

import ast
from collections.abc import Iterator
from typing import Literal

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._ast_scope import walk_statement_scope
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
_ClientBindingStatus = Literal["supported", "shadowed", "unbound"]
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

        Request-tainted URLs at supported HTTP clients can expose cloud metadata or reach internal services.

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
            Findings for supported URL arguments marked tainted. Empty when the file is skipped or no supported URL argument is marked tainted.
        """
        # The source markers avoid a taint pass on files unlikely to contain a supported client call.
        if not isinstance(unit.tree, ast.Module) or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        taint_map = TaintAnalyser(_SSRF_SANITISERS).analyse_tree(unit.tree)
        definition = self.definition()
        findings: list[Finding] = []
        # Each parsed call is checked against the small matrix shown in rule documentation.
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            user_url = _supported_http_client_url_argument(
                node,
                tree=unit.tree,
            )
            # A documented client call counts only when request data can still reach its URL argument.
            if user_url is None or not taint_map.is_tainted(user_url):
                continue
            findings.append(_build_finding(definition, unit, node))
        return findings


def _supported_http_client_url_argument(
    call: ast.Call,
    *,
    tree: ast.Module,
) -> ast.expr | None:
    """Return the URL expression for a documented direct HTTP-client call.

    Args:
        call: User call expression being checked as a possible sink.
        tree: Parsed module used to prove the receiver's same-unit import binding.

    Returns:
        The URL expression from a supported positional slot or the url keyword.
        None when the target is unsupported, its client import cannot be verified, or the URL argument is missing.
    """
    target = call_target_name(call)
    # Dynamic callees provide no stable target spelling for import-binding verification.
    if target is None:
        return None
    required_binding = _required_import_binding(target)
    # A familiar spelling is not proof that the receiver is the documented client.
    if required_binding is None or not _call_has_supported_binding(
        call,
        tree,
        binding_name=required_binding[0],
        canonical_import=required_binding[1],
    ):
        return None
    # Direct verbs take their URL first or from the explicit url keyword.
    if target in _HTTP_VERB_TARGETS:
        return _positional_or_keyword_url(call, positional_index=0)
    # Generic request methods take the method first and the URL second, or use the url keyword.
    if target in _REQUEST_METHOD_TARGETS:
        return _positional_or_keyword_url(call, positional_index=1)
    # Qualified and bare urlopen take the URL first once their import binding is verified.
    if target in (_QUALIFIED_URLOPEN_TARGET, "urlopen"):
        return _positional_or_keyword_url(call, positional_index=0)
    return None


def _required_import_binding(target: str) -> tuple[str, str] | None:
    """Return the lexical root and canonical import used to verify a supported target.

    Args:
        target: Bare or dotted call spelling used to select the required import.

    Returns:
        Binding/canonical import pair, or None for an unsupported call target.
    """
    if target in _HTTP_VERB_TARGETS or target in _REQUEST_METHOD_TARGETS:
        module_name = target.split(".", 1)[0]
        return module_name, module_name
    if target == _QUALIFIED_URLOPEN_TARGET:
        return "urllib", "urllib.request"
    if target == "urlopen":
        return "urlopen", "urllib.request.urlopen"
    return None


def _call_has_supported_binding(
    call: ast.Call,
    tree: ast.Module,
    *,
    binding_name: str,
    canonical_import: str,
) -> bool:
    """Resolve the nearest lexical binding without importing user code.

    Args:
        call: Supported textual call target being checked.
        tree: Parsed module that ultimately owns global bindings.
        binding_name: Root identifier visible at the call site.
        canonical_import: Exact direct import that proves the real client.

    Returns:
        True only when the nearest binding is an unambiguous direct import.
    """
    ancestor = getattr(call, "parent", None)
    crossed_function_scope = False
    while ancestor is not None and not isinstance(ancestor, ast.Module):
        if isinstance(ancestor, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            status = _scope_client_binding_status(
                ancestor,
                binding_name=binding_name,
                canonical_import=canonical_import,
                call_line=call.lineno,
                call_column=call.col_offset,
                require_prior_import=not crossed_function_scope,
            )
            if status != "unbound":
                return status == "supported"
            crossed_function_scope = True
        elif isinstance(ancestor, ast.ClassDef) and not crossed_function_scope:
            status = _scope_client_binding_status(
                ancestor,
                binding_name=binding_name,
                canonical_import=canonical_import,
                call_line=call.lineno,
                call_column=call.col_offset,
                require_prior_import=True,
            )
            if status != "unbound":
                return status == "supported"
        ancestor = getattr(ancestor, "parent", None)
    module = ancestor if isinstance(ancestor, ast.Module) else tree
    return (
        _scope_client_binding_status(
            module,
            binding_name=binding_name,
            canonical_import=canonical_import,
            call_line=call.lineno,
            call_column=call.col_offset,
            require_prior_import=not crossed_function_scope,
        )
        == "supported"
    )


def _scope_client_binding_status(
    scope: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    *,
    binding_name: str,
    canonical_import: str,
    call_line: int,
    call_column: int,
    require_prior_import: bool,
) -> _ClientBindingStatus:
    """Classify one scope's binding as imported, shadowed, or absent.

    Args:
        scope: Scope searched for an effective binding of the receiver name.
        binding_name: Receiver root being resolved.
        canonical_import: Exact supported module or callable import.
        call_line: Source line of the candidate sink.
        call_column: Source column of the candidate sink.
        require_prior_import: Whether bindings in this scope are checked against the call's source position.

    Returns:
        supported for an effective direct canonical import or shadowed for a binding that prevents trusting the import.
        unbound when the scope supplies no effective binding, so the caller can check an enclosing scope.
        A later effective canonical import restores trust; later function-local bindings can shadow an earlier call.
    """
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and binding_name in _parameter_names(scope.args):
        return "shadowed"
    has_retroactive_local_bindings = isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and not _has_external_binding_declaration(
        scope, binding_name
    )
    direct_statement_ids = {id(statement) for statement in _scope_statements(scope)}
    # Keep scanning because a later effective canonical import can restore trust after a shadow.
    status: _ClientBindingStatus = "unbound"
    for node in _scope_nodes(scope):
        is_after_call = require_prior_import and _is_after_call(
            node,
            call_line=call_line,
            call_column=call_column,
        )
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            import_status = _import_binding_status(
                node,
                binding_name=binding_name,
                canonical_import=canonical_import,
                is_direct_statement=id(node) in direct_statement_ids,
                is_after_call=is_after_call,
                should_ignore_later_binding=(is_after_call and not has_retroactive_local_bindings),
            )
            # Imports ignored at this call site must leave earlier binding evidence intact.
            if import_status != "unbound":
                status = import_status
            continue
        if _is_call_shadowed_by_binding(
            node,
            binding_name=binding_name,
            is_after_call=is_after_call,
            has_retroactive_local_bindings=has_retroactive_local_bindings,
        ):
            status = "shadowed"
    return status


def _scope_statements(
    scope: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> list[ast.stmt]:
    """Return statements executed directly by one lexical scope.

    Args:
        scope: Scope whose compound children must not masquerade as direct imports.

    Returns:
        Direct statement list; lambdas have an expression body and return empty.
    """
    if isinstance(scope, ast.Lambda):
        return []
    return scope.body


def _scope_nodes(
    scope: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> Iterator[ast.AST]:
    """Yield nodes in one scope while stopping at nested lexical bodies.

    Args:
        scope: Scope whose bindings are being classified.

    Yields:
        Nodes from the scope body, including nested scope nodes without their descendants.
    """
    if isinstance(scope, ast.Lambda):
        yield from walk_statement_scope(scope.body)
        return
    for statement in scope.body:
        yield from walk_statement_scope(statement)


def _import_binding_status(
    statement: ast.Import | ast.ImportFrom,
    *,
    binding_name: str,
    canonical_import: str,
    is_direct_statement: bool,
    is_after_call: bool,
    should_ignore_later_binding: bool,
) -> _ClientBindingStatus:
    """Classify one import statement relative to the candidate call.

    Args:
        statement: Import syntax in the current lexical scope.
        binding_name: Receiver root being resolved.
        canonical_import: Exact supported module or callable import.
        is_direct_statement: Whether the import is a direct statement in this scope's body.
        is_after_call: Whether source order places the import after the call in a scope where order matters.
        should_ignore_later_binding: Whether source order makes that import irrelevant.

    Returns:
        The supported status for a qualifying client import, shadowed for an import that may obscure the client binding,
        or unbound when this statement leaves the prior binding status unchanged.
    """
    if should_ignore_later_binding:
        return "unbound"
    if isinstance(statement, ast.ImportFrom) and any(alias.name == "*" for alias in statement.names):
        return "shadowed"
    status: _ClientBindingStatus = "unbound"
    for imported_alias in statement.names:
        if _visible_import_name(statement, imported_alias) != binding_name:
            continue
        if not is_direct_statement or is_after_call or not _is_exact_supported_import(statement, imported_alias, canonical_import):
            return "shadowed"
        status = "supported"
    return status


def _is_call_shadowed_by_binding(
    node: ast.AST,
    *,
    binding_name: str,
    is_after_call: bool,
    has_retroactive_local_bindings: bool,
) -> bool:
    """Return whether one non-import binding invalidates the candidate call.

    Args:
        node: Scope-limited syntax that may bind the receiver.
        binding_name: Supported receiver root whose trust is being protected.
        is_after_call: Whether source-order checks place this binding after the call. False when source order is ignored.
        has_retroactive_local_bindings: Whether local names bind for the whole scope.

    Returns:
        True for a matching binding at or before the call, or at any position when source order is ignored.
        When order is checked, only scope-wide local names can shadow an earlier call. Later attribute changes leave that call unaffected.
    """
    if not _has_name_binding(node, binding_name):
        return False
    if not is_after_call:
        return True
    if isinstance(node, ast.Attribute):
        return False
    return has_retroactive_local_bindings


def _has_external_binding_declaration(
    scope: ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
    binding_name: str,
) -> bool:
    """Return whether a function explicitly resolves the name outside itself.

    Args:
        scope: Scope whose global/nonlocal declarations are inspected.
        binding_name: Receiver root that may be external to the function.

    Returns:
        True when global or nonlocal removes retroactive local binding.
    """
    if not isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        return False
    return any(isinstance(node, (ast.Global, ast.Nonlocal)) and binding_name in node.names for node in _scope_nodes(scope))


def _is_after_call(node: ast.AST, *, call_line: int, call_column: int) -> bool:
    """Compare a binding's source coordinates with the candidate call.

    Args:
        node: Binding syntax whose missing position fields default to the call's corresponding coordinates.
        call_line: One-based line where the call starts.
        call_column: Zero-based column where the call starts.

    Returns:
        True when the resulting source coordinates sort after the call's coordinates; False otherwise.
    """
    node_line = getattr(node, "lineno", call_line)
    node_column = getattr(node, "col_offset", call_column)
    return (node_line, node_column) > (call_line, call_column)


def _parameter_names(arguments: ast.arguments) -> set[str]:
    """Collect all parameter names so callers can check whether a client import is shadowed.

    Args:
        arguments: Parameters declared by the function or lambda being checked for shadowing.

    Returns:
        Declared names of positional and keyword-only parameters, including any variadic positional and variadic keyword parameters.
    """
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    names = {parameter.arg for parameter in parameters}
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return names


def _visible_import_name(statement: ast.Import | ast.ImportFrom, alias: ast.alias) -> str:
    """Return the identifier one import binds in its current scope.

    Args:
        statement: Import form controlling dotted-name binding semantics.
        alias: Import entry whose explicit alias takes precedence over its original name.

    Returns:
        Visible lexical name, including explicit aliases.
    """
    if alias.asname is not None:
        return alias.asname
    if isinstance(statement, ast.Import):
        return alias.name.split(".", 1)[0]
    return alias.name


def _is_exact_supported_import(
    statement: ast.Import | ast.ImportFrom,
    alias: ast.alias,
    canonical_import: str,
) -> bool:
    """Return whether one unaliased import exactly establishes client trust.

    Args:
        statement: User import statement containing the candidate alias.
        alias: Imported module or member that binds the receiver root.
        canonical_import: Required canonical module or callable.

    Returns:
        True for an unaliased import of the required module or a submodule, or for the absolute from-import of urllib.request.urlopen.
    """
    if alias.asname is not None:
        return False
    if canonical_import == "urllib.request.urlopen":
        return isinstance(statement, ast.ImportFrom) and statement.level == 0 and statement.module == "urllib.request" and alias.name == "urlopen"
    if not isinstance(statement, ast.Import):
        return False
    # Importing requests.adapters binds the same requests package as importing requests directly.
    # Either import therefore establishes the client binding.
    return alias.name == canonical_import or alias.name.startswith(f"{canonical_import}.")


def _has_name_binding(node: ast.AST, binding_name: str) -> bool:
    """Check whether syntax binds or deletes a receiver name, or modifies its attributes.

    Args:
        node: Syntax from the scope being checked for a receiver binding or attribute change.
        binding_name: Supported receiver root whose trust is being protected.

    Returns:
        True for a matching name or attribute write or deletion, function or class name, exception handler name, or pattern capture.
    """
    if isinstance(node, ast.Name):
        return node.id == binding_name and isinstance(node.ctx, (ast.Store, ast.Del))
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
        return _attribute_root_name(node) == binding_name
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return node.name == binding_name
    if isinstance(node, ast.ExceptHandler):
        return node.name == binding_name
    if isinstance(node, (ast.MatchAs, ast.MatchStar)):
        return node.name == binding_name
    return isinstance(node, ast.MatchMapping) and node.rest == binding_name


def _attribute_root_name(attribute: ast.Attribute) -> str | None:
    """Find the receiver name behind an attribute write or deletion.

    Args:
        attribute: Assignment or deletion target such as requests.get.

    Returns:
        Root identifier, or None if the attribute chain does not start at a name.
    """
    current: ast.expr = attribute
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _positional_or_keyword_url(call: ast.Call, *, positional_index: int) -> ast.expr | None:
    """Return a supported positional URL before falling back to the named url argument.

    Args:
        call: Supported HTTP-client call from the user's source.
        positional_index: Argument slot used by that client method.

    Returns:
        URL expression, or None when the user supplied no supported URL argument.
    """
    # If both forms appear in source, only the positional expression is checked for taint.
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
        Finding with SSRF remediation, the call-target label and HTTP-client security metadata.
    """
    target = call_target_name(call) or "?"
    return Finding(
        rule_id=definition.id,
        message=(f"`{target}(...)` receives a user-controlled URL - SSRF risk via internal services, cloud metadata, or other reachable targets."),
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
