"""``dead-code.exported-but-unreferenced`` - export is not use, in full-project scans.

A public top-level function or class whose only project-wide references are
its own definition, ``__all__`` membership, and bare re-export imports is
dead code that "looks used": the export plumbing keeps reference counters
non-zero while no call site exists anywhere. In full-project scans this rule
classifies every reference to a public name and flags symbols with no real
use; in partial scans (narrowed paths, ``--diff``/``--since``) it suppresses
itself entirely, because out-of-scope callers are invisible (ADR-025 scope
honesty - the run-level partial-context caveat still renders).

Reference model (name-based, conservative): any load of the name - calls,
attribute access (``module.symbol``), decorator usage, base classes,
annotations, ``getattr(x, "symbol")`` string literals - counts as use, in any
file including tests. Aliased imports (``from m import foo as bar``) count as
use of ``foo`` (the alias indicates intent the model cannot follow). Same-name
symbols in different modules collapse together, so collisions produce false
negatives, never false positives.

Exemptions: underscore and dunder names, framework-decorated definitions
(pytest fixtures, Click commands, routes, ...), the ``allowlists.deadCode``
config (symbols/decorators/paths, ADR-015), and the rule's
``entryPointPatterns`` option (fnmatch globs over the symbol name for
plugin/entry-point registration conventions).
"""

import ast
import fnmatch
from dataclasses import dataclass

from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import has_framework_decorator
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition

_REMEDIATION = (
    "Delete the symbol and its re-exports, or keep it deliberately: allowlist "
    "it under allowlists.deadCode.symbols, or add the registration convention "
    "that consumes it to this rule's entryPointPatterns option."
)


@dataclass(frozen=True, slots=True)
class _ExportCandidate:
    """One public top-level definition eligible for the unreferenced check."""

    name: str
    unit: AnalysisUnit
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


class ExportedButUnreferencedRule:
    """Detect public symbols whose only references are definition, __all__, re-exports."""

    ID = "dead-code.exported-but-unreferenced"

    def definition(self) -> RuleDefinition:
        """Describe the exported-but-unreferenced rule as a medium-confidence advisory.

        Medium confidence: the reference model is name-based rather than
        import-resolved, so it errs toward false negatives (any same-name
        use anywhere counts), and it only runs with full-project context.

        Returns:
            Definition for the exported-but-unreferenced rule under the
            dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Exported but unreferenced",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"entryPointPatterns": []},
        )

    def analyse_project(self, units: list[AnalysisUnit], context: RuleContext) -> list[Finding]:
        """Flag public top-level symbols with no real reference across the project.

        Args:
            units: Parsed project units to inspect together.
            context: Rule execution context carrying ``scan_scope`` and config.

        Returns:
            Findings for export-only public symbols; empty for partial scans.
        """
        if context.scan_scope != "full-project":
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        entry_point_patterns = tuple(settings.string_list_option("entryPointPatterns"))
        allowlist = context.config.dead_code_allowlist
        parsed_units = [(unit, unit.tree) for unit in units if isinstance(unit.tree, ast.Module)]
        candidates = _export_candidates(parsed_units)
        if not candidates:
            return []
        used_names = _used_names([tree for _, tree in parsed_units])
        findings: list[Finding] = []
        for candidate in candidates:
            if candidate.name in used_names:
                continue
            if _is_exempt(candidate, allowlist, entry_point_patterns):
                continue
            findings.append(_build_finding(definition, candidate))
        return findings


def _export_candidates(
    parsed_units: list[tuple[AnalysisUnit, ast.Module]],
) -> list[_ExportCandidate]:
    candidates: list[_ExportCandidate] = []
    for unit, tree in parsed_units:
        if _is_test_unit(unit):
            continue
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if node.name.startswith("_"):
                continue
            candidates.append(_ExportCandidate(name=node.name, unit=unit, node=node))
    return candidates


def _is_test_unit(unit: AnalysisUnit) -> bool:
    display_path = unit.file.display_path.replace("\\", "/")
    parts = display_path.split("/")
    return "tests" in parts[:-1] or parts[-1].startswith("test_") or parts[-1] == "conftest.py"


def _used_names(trees: list[ast.Module]) -> set[str]:
    """Collect every name with a non-export reference anywhere in the project.

    Export plumbing deliberately does not count: ``__all__`` entries are
    string constants (never ``Name`` loads), and plain import aliases are
    skipped. Everything else - loads, attribute access, ``getattr`` string
    literals, aliased imports, and names inside quoted/forward-reference
    annotations - marks the name as used.
    """
    used: set[str] = set()
    for tree in trees:
        for node in ast.walk(tree):
            used.update(_node_references(node))
    return used


def _node_references(node: ast.AST) -> set[str]:
    """References a single node contributes (loads, attrs, imports, annotations)."""
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return {alias.name.split(".")[-1] for alias in node.names if alias.asname is not None}
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return _forward_reference_names(node.returns)
    if isinstance(node, (ast.arg, ast.AnnAssign)):
        return _forward_reference_names(node.annotation)
    literal = _getattr_string_literal(node)
    return {literal} if literal is not None else set()


def _getattr_string_literal(node: ast.AST) -> str | None:
    if not (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
    ):
        return None
    literal = node.args[1]
    if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
        return literal.value
    return None


def _forward_reference_names(annotation: ast.expr | None) -> set[str]:
    """Names referenced inside an annotation, including quoted forward refs.

    A fully quoted annotation (``-> "Payload"``) or a quoted element inside a
    generic (``list["Payload"]``) is an ``ast.Constant`` string that the plain
    ``Name`` walk never sees. Each string constant in the annotation is parsed
    as an expression and its ``Name`` loads count as references, so the rule's
    "annotations count as use" contract holds for forward references too.
    """
    if annotation is None:
        return set()
    names: set[str] = set()
    for node in ast.walk(annotation):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.update(_names_in_expression(node.value))
    return names


def _names_in_expression(text: str) -> set[str]:
    try:
        parsed = ast.parse(text, mode="eval")
    except SyntaxError:
        return set()
    return {node.id for node in ast.walk(parsed) if isinstance(node, ast.Name)}


def _is_exempt(
    candidate: _ExportCandidate,
    allowlist: DeadCodeAllowlist,
    entry_point_patterns: tuple[str, ...],
) -> bool:
    if has_framework_decorator(candidate.node):
        return True
    if allowlist.matches_path(candidate.unit.file.display_path):
        return True
    if allowlist.matches_symbol(candidate.name):
        return True
    decorator_names = tuple(
        name
        for decorator in candidate.node.decorator_list
        for name in _decorator_name_forms(decorator)
    )
    if decorator_names and allowlist.matches_decorator(decorator_names):
        return True
    return any(fnmatch.fnmatchcase(candidate.name, pattern) for pattern in entry_point_patterns)


def _decorator_name_forms(decorator: ast.expr) -> tuple[str, ...]:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    parts: list[str] = []
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    if not parts:
        return ()
    dotted = ".".join(reversed(parts))
    return (dotted, parts[0]) if dotted != parts[0] else (dotted,)


def _build_finding(definition: RuleDefinition, candidate: _ExportCandidate) -> Finding:
    kind = "class" if isinstance(candidate.node, ast.ClassDef) else "function"
    return Finding(
        rule_id=definition.id,
        message=(
            f"Public {kind} {candidate.name!r} has no reference beyond its definition, "
            "__all__ membership, and re-export imports in this full-project scan; it "
            "needs a caller, an entry-point registration, or removal."
        ),
        file_path=candidate.unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.node.end_lineno,
        symbol=candidate.name,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={"symbol": candidate.name, "kind": kind, "scope": "full-project"},
    )
