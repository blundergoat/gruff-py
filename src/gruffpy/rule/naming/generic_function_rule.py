"""Vague function names that don't describe what the function does.

Flagged: ``process``, ``handle``, ``do``, ``run``, ``execute``, ``perform``,
``apply``, ``manage``, ``operate`` as standalone function/method names.
Configurable via ``genericFunctions`` per-rule option.

Allowed when used as a verb-prefix: ``process_payment``, ``handle_request``,
``execute_query`` are fine because they specify what is processed/handled.
Required methods on explicitly imported Django commands, docutils directives,
threads and logging handlers are also allowed when the import is unambiguous.
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
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_DEFAULT_GENERIC: tuple[str, ...] = (
    "process",
    "handle",
    "do",
    "run",
    "execute",
    "perform",
    "apply",
    "manage",
    "operate",
)

_REQUIRED_METHODS: dict[str, frozenset[str]] = {
    "django.core.management.base.BaseCommand": frozenset({"handle", "execute"}),
    "docutils.parsers.rst.Directive": frozenset({"run"}),
    "threading.Thread": frozenset({"run"}),
    "logging.Handler": frozenset({"handle"}),
}


def _import_binding(node: ast.Import | ast.ImportFrom, alias: ast.alias) -> tuple[str, str]:
    """Map one import alias to its local name and absolute path.

    Args:
        node: Import statement whose relative level is checked by the caller.
        alias: Imported name with an optional local alias.

    Returns:
        Local binding and imported path; a dotted unaliased import binds its
        first component, matching Python's import semantics.
    """
    if isinstance(node, ast.ImportFrom):
        return alias.asname or alias.name, f"{node.module}.{alias.name}"
    local = alias.asname or alias.name.split(".")[0]
    return local, alias.name if alias.asname else local


def _framework_imports(tree: ast.AST) -> dict[str, str]:
    """Resolve module imports conservatively for the required-method exemption.

    Args:
        tree: Parsed source whose direct module imports supply base identities.

    Returns:
        Local names mapped to imported paths, excluding any name rebound or
        shadowed elsewhere in the source. Conditional imports are not resolved.
    """
    if not isinstance(tree, ast.Module):
        return {}
    imports = [node for node in tree.body if isinstance(node, ast.Import | ast.ImportFrom)]
    bindings: dict[str, str] = {}
    blocked: set[str] = set()
    for node in imports:
        for alias in node.names:
            if alias.name == "*":
                return {}
            local, target = _import_binding(node, alias)
            if local in bindings or isinstance(node, ast.ImportFrom) and node.level:
                blocked.add(local)
            bindings[local] = target
    for descendant in ast.walk(tree):
        if isinstance(descendant, ast.Name) and isinstance(descendant.ctx, ast.Store | ast.Del):
            blocked.add(descendant.id)
        elif isinstance(descendant, ast.arg):
            blocked.add(descendant.arg)
        elif isinstance(descendant, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.ExceptHandler):
            if descendant.name is not None:
                blocked.add(descendant.name)
        elif isinstance(descendant, ast.Import | ast.ImportFrom) and descendant not in imports:
            blocked.update(alias.asname or alias.name.split(".")[0] for alias in descendant.names)
    return {local: target for local, target in bindings.items() if local not in blocked}


def _is_required_method(node: ast.FunctionDef | ast.AsyncFunctionDef, bindings: dict[str, str]) -> bool:
    """Check a direct method against the required names of imported bases.

    Args:
        node: Function whose immediate parent determines whether it is a method.
        bindings: Unambiguous absolute imports from the current source file.

    Returns:
        True only for a recognized base and its exact required method name.
        Local subclasses and transitive inheritance are not resolved.
    """
    parent = getattr(node, "parent", None)
    if not isinstance(parent, ast.ClassDef):
        return False
    for base in parent.bases:
        parts = ast.unparse(base).split(".")
        imported = bindings.get(parts[0])
        if imported is not None:
            qualified = ".".join([imported, *parts[1:]])
            if node.name in _REQUIRED_METHODS.get(qualified, frozenset()):
                return True
    return False


class GenericFunctionRule(Rule):
    """Flag functions named with vague verbs like `process` or `handle` without an object."""

    ID = "naming.generic-function"

    def definition(self) -> RuleDefinition:
        """Describe the generic-function rule with a configurable verb blocklist.

        Returns:
            Definition under the naming pillar; the blocklist is exposed via
            the ``genericFunctions`` option.
        """
        return RuleDefinition(
            id=self.ID,
            name="Generic function name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_enabled=False,
            default_options={"genericFunctions": list(_DEFAULT_GENERIC)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag configured generic verbs outside recognized required methods.

        Single-token check is deliberate: ``process_payment`` passes
        (two tokens) but ``process`` alone fails. The blocklist defaults to
        common contentless verbs (``process``, ``handle``, ``do``, ``run``,
        ``execute``, ``perform``, ``apply``, ``manage``, ``operate``).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the
                ``genericFunctions`` option.

        Returns:
            One finding per generic function without a recognized required-method
            contract.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        configured = settings.options.get("genericFunctions", list(_DEFAULT_GENERIC))
        if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
            configured = list(_DEFAULT_GENERIC)
        generic = frozenset(configured)
        bindings = _framework_imports(unit.tree)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            tokens = lower_tokens(node.name)
            if len(tokens) != 1:
                continue
            if tokens[0] not in generic:
                continue
            if _is_required_method(node, bindings):
                continue
            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Function {symbol!r} has a generic name; add a domain noun (e.g. ``process_payment``)."),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=f"Rename {node.name!r} to ``{node.name}_<noun>``.",
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"identifier": node.name},
                ),
            )
        return findings
