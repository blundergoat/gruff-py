"""``security.django-mark-safe`` - Django XSS opt-out applied to dynamic content.

Django's ``mark_safe()`` (and the related ``SafeString``, ``SafeText``,
``format_html``) tell the template engine to skip auto-escaping. Calling
them on a string literal is fine (the developer is opting out for a known
trusted constant); calling them on a variable, an f-string, or a
``.format()`` result is an XSS sink - every value flowing in is rendered
without escaping.

Matched shapes (Django framework gate required):

- ``mark_safe(<non-literal>)``
- ``SafeString(<non-literal>)``
- ``SafeText(<non-literal>)``
- ``format_html(<non-literal-template>, ...)``

Calls whose first argument is a plain string literal (``mark_safe("<br>")``)
or an explicit escape-returning call (``mark_safe(escape(x))``) are skipped.
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
from gruffpy.rule.security._security_node_helper import (
    call_target_name,
    frameworks_in_use,
    is_string_literal,
)

_DJANGO_GATE: frozenset[str] = frozenset({"django"})
_MARK_SAFE_LEAVES: frozenset[str] = frozenset({"mark_safe", "SafeString", "SafeText", "format_html"})
_SOURCE_NEEDLES: tuple[str, ...] = ("mark_safe", "SafeString", "SafeText", "format_html")
_ESCAPE_LEAVES: frozenset[str] = frozenset({"escape", "conditional_escape"})
# Django helpers whose output an escaped join may combine; ``format_html`` escapes its arguments.
_DJANGO_HTML_HELPERS: frozenset[str] = frozenset({"escape", "conditional_escape", "format_html"})
# Definitions that open their own name scope; lambdas and comprehensions are scanned as part of the enclosing one.
_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
_REMEDIATION = (
    "Either keep `mark_safe` arguments as plain string literals, or call "
    "`django.utils.html.escape()` / `conditional_escape()` on user-controlled "
    "values before marking them safe. For HTML templating with safe escaping, "
    "use `format_html('<b>{}</b>', value)` (literal template, escaped args)."
)


class DjangoMarkSafeRule(Rule):
    """Detect Django XSS opt-out calls applied to non-literal content."""

    ID = "security.django-mark-safe"

    def definition(self) -> RuleDefinition:
        """Describe the Django mark-safe rule as a medium-confidence WARNING.

        WARNING severity because the call may be legitimate when the input
        is provably escaped (e.g. ``escape(x)`` chain); medium confidence
        because the rule cannot prove the upstream provenance of the value
        being marked safe - only the syntactic absence of a literal or
        escape call.

        Returns:
            Definition for the Django mark-safe rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Django mark_safe on dynamic content",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag mark_safe / SafeString / SafeText / format_html on non-literal input.

        Gated to files importing Django. Skips calls whose first argument
        is a plain string literal or a call to ``escape`` /
        ``conditional_escape`` (both produce strings the developer has
        explicitly escaped).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unsafe mark-safe-family call.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        if not (frameworks_in_use(unit.tree) & _DJANGO_GATE):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        scopes = _call_scopes(unit.tree)
        html_helpers = _django_html_helpers(unit.tree, unit.file.display_path)
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            leaf = _mark_safe_leaf(node)
            if leaf is None or not node.args:
                continue
            if _has_safe_first_arg(node.args[0], scopes[id(node)], html_helpers):
                continue
            findings.append(_build_finding(definition, unit, node, leaf))
        return findings


def _mark_safe_leaf(call: ast.Call) -> str | None:
    target = call_target_name(call)
    if target is None:
        return None
    leaf = target.split(".")[-1]
    if leaf not in _MARK_SAFE_LEAVES:
        return None
    return leaf


def _has_safe_first_arg(first: ast.expr, scope: ast.AST, html_helpers: dict[str, str]) -> bool:
    if is_string_literal(first):
        return True
    if isinstance(first, ast.Call):
        target = call_target_name(first)
        if target is not None and target.split(".")[-1] in _ESCAPE_LEAVES:
            return True
        return _is_escaped_join(first, html_helpers)
    return isinstance(first, ast.Name) and _has_only_literal_bindings(scope, first.id)


def _call_scopes(tree: ast.AST) -> dict[int, ast.AST]:
    """Map each call to the function, class or module scope whose local names it reads.

    Decorators, defaults, annotations and class bases run in the enclosing scope, so only a definition's body
    belongs to the definition's own scope. The walk uses an explicit stack, so deeply nested code cannot exhaust
    recursion.
    """
    scopes: dict[int, ast.AST] = {}
    pending: list[tuple[ast.AST, ast.AST]] = [(tree, tree)]
    while pending:
        node, scope = pending.pop()
        if isinstance(node, ast.Call):
            scopes[id(node)] = scope
        body = {id(statement) for statement in node.body} if isinstance(node, _SCOPE_NODES) else set()
        pending.extend((child, node if id(child) in body else scope) for child in ast.iter_child_nodes(node))
    return scopes


def _has_only_literal_bindings(scope: ast.AST, name: str) -> bool:
    """Report whether every binding of a name in one scope is a plain assignment of a string literal.

    Contract invariant: the name must be bound in the call's own scope, and parameters, augmented assignment,
    annotated or unpacked targets, loop, ``with`` and ``except`` targets, walrus, imports, ``del``, nested
    definitions of the name and any ``global``/``nonlocal`` declaration of it keep the warning.
    """
    if isinstance(scope, ast.FunctionDef | ast.AsyncFunctionDef) and name in _parameter_names(scope.args):
        return False
    literal_bindings = 0
    pending: list[ast.AST] = list(getattr(scope, "body", []))
    while pending:
        node = pending.pop()
        literal_binding = _is_literal_binding(node, name)
        if literal_binding is False:
            return False
        if literal_binding is True:
            literal_bindings += 1
            continue
        pending.extend(_same_scope_children(node))
    return literal_bindings > 0 and not _has_outer_binding_declaration(scope, name)


def _is_literal_binding(node: ast.AST, name: str) -> bool | None:
    """Return True for ``name = "literal"``, False for any other binding of the name, and None otherwise."""
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name:
        return is_string_literal(node.value)
    if isinstance(node, ast.Name) and node.id == name:
        return False if isinstance(node.ctx, ast.Store | ast.Del) else None
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef) and node.name == name:
        return False
    if isinstance(node, ast.Lambda) and name in _parameter_names(node.args):
        return False
    if isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == name:
        return False
    if isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name == name:
        return False
    if isinstance(node, ast.MatchMapping) and node.rest == name:
        return False
    return None


def _same_scope_children(node: ast.AST) -> list[ast.AST]:
    """Return a node's children that run in the same scope; nested definition bodies bind their own names."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        body = {id(statement) for statement in node.body}
        return [child for child in ast.iter_child_nodes(node) if id(child) not in body]
    return list(ast.iter_child_nodes(node))


def _has_outer_binding_declaration(scope: ast.AST, name: str) -> bool:
    """Report whether any ``global`` or ``nonlocal`` declaration inside the scope names the name."""
    return any(isinstance(node, ast.Global | ast.Nonlocal) and name in node.names for node in ast.walk(scope))


def _parameter_names(arguments: ast.arguments) -> set[str]:
    """Return every parameter name a function or lambda binds."""
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs, arguments.vararg, arguments.kwarg]
    return {parameter.arg for parameter in parameters if parameter is not None}


def _django_html_helpers(tree: ast.AST, display_path: str) -> dict[str, str]:
    """Map each call name that resolves to Django's own ``escape``, ``conditional_escape`` or ``format_html`` to that helper.

    Contract invariant: only imports from ``django.utils.html``, or the module-level definitions inside Django's own
    ``django/utils/html.py``, count; the value is the helper's Django name, so an import renamed onto another helper's
    name keeps its real role, and a name the file also binds any other way is not trusted.
    """
    trusted: dict[str, str] = {}
    other_bindings: set[str] = set()
    is_django_html_module = display_path == "django/utils/html.py" or display_path.endswith("/django/utils/html.py")
    module_body = {id(statement) for statement in getattr(tree, "body", [])}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            _collect_from_import(node, trusted, other_bindings)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "django.utils.html":
                    prefix = alias.asname or alias.name
                    trusted.update({f"{prefix}.{helper}": helper for helper in _DJANGO_HTML_HELPERS})
                else:
                    other_bindings.add(alias.asname or alias.name.split(".")[0])
        elif (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name in _DJANGO_HTML_HELPERS
            and is_django_html_module
            and id(node) in module_body
        ):
            trusted[node.name] = node.name
        else:
            other_bindings.update(_html_shadowing_names(node))
    return {name: helper for name, helper in trusted.items() if name.split(".")[0] not in other_bindings and "*" not in other_bindings}


def _html_shadowing_names(node: ast.AST) -> set[str]:
    """Collect bindings that prevent an imported helper or module from proving escaped output."""
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {node.name}
    if isinstance(node, ast.arg):
        return {node.arg}
    if isinstance(node, ast.Global | ast.Nonlocal):
        return set(node.names)
    if isinstance(node, ast.ExceptHandler | ast.MatchAs | ast.MatchStar) and node.name:
        return {node.name}
    if isinstance(node, ast.MatchMapping) and node.rest:
        return {node.rest}
    if isinstance(node, ast.Name | ast.Attribute) and isinstance(node.ctx, ast.Store | ast.Del):
        while isinstance(node, ast.Attribute):
            node = node.value
        if isinstance(node, ast.Name):
            return {node.id}
    return set()


def _collect_from_import(node: ast.ImportFrom, trusted: dict[str, str], other_bindings: set[str]) -> None:
    """Sort one ``from ... import`` into Django-bound helper names and look-alike bindings."""
    for alias in node.names:
        local_name = alias.asname or alias.name
        if node.level == 0 and node.module == "django.utils" and alias.name == "html":
            trusted.update({f"{local_name}.{helper}": helper for helper in _DJANGO_HTML_HELPERS})
        elif node.level == 0 and node.module == "django.utils.html" and alias.name in _DJANGO_HTML_HELPERS:
            trusted[local_name] = alias.name
        else:
            other_bindings.add(local_name)


def _is_escaped_join(call: ast.Call, html_helpers: dict[str, str]) -> bool:
    """Report whether a ``.join`` builds markup only from escaped or Django-formatted pieces.

    Contract invariant: the separator must be a string literal or a Django-bound escape call, and every joined item
    a string literal, a Django-bound ``escape``, ``conditional_escape`` or ``format_html`` call, or a conditional
    choosing between two such items; a ``format_html`` item's own template is still judged by its own finding.
    """
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "join" and len(call.args) == 1 and not call.keywords):
        return False
    separator = call.func.value
    if not (is_string_literal(separator) or _is_django_html_call(separator, html_helpers, _ESCAPE_LEAVES)):
        return False
    items = _joined_items(call.args[0])
    return items is not None and all(_is_safe_join_item(item, html_helpers) for item in items)


def _is_safe_join_item(item: ast.expr, html_helpers: dict[str, str]) -> bool:
    """Report whether one joined item is a literal, a Django-bound helper call, or a choice between two such items."""
    if isinstance(item, ast.IfExp):
        return _is_safe_join_item(item.body, html_helpers) and _is_safe_join_item(item.orelse, html_helpers)
    return is_string_literal(item) or _is_django_html_call(item, html_helpers, _DJANGO_HTML_HELPERS)


def _joined_items(iterable: ast.expr) -> list[ast.expr] | None:
    """Return the item expressions of a comprehension or literal collection, or None for any other iterable."""
    if isinstance(iterable, ast.GeneratorExp | ast.ListComp | ast.SetComp):
        return [iterable.elt]
    if isinstance(iterable, ast.List | ast.Tuple | ast.Set):
        return list(iterable.elts)
    return None


def _is_django_html_call(node: ast.expr, html_helpers: dict[str, str], leaves: frozenset[str]) -> bool:
    """Report whether an expression calls one of the named Django helpers through a Django-bound name."""
    if not isinstance(node, ast.Call):
        return False
    target = call_target_name(node)
    return target is not None and html_helpers.get(target) in leaves


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    leaf: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(f"`{leaf}(...)` applied to non-literal content - XSS risk if the value is user-controlled."),
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
            "leaf": leaf,
            **finding_security_metadata(
                definition.id,
                source_label="user-html-input",
                sink_label="django-safe-marker",
            ),
        },
    )
