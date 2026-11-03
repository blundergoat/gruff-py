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
file including tests and files ``paths.ignore`` keeps out of the report, which
contribute references but never produce a finding. Aliased imports (``from m import foo as bar``) count as
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
        Opt-in: a library's public API exists for callers outside the
        repository, and packaging entry points, string registration and
        framework hooks are references the scan cannot see, so on the family
        corpus one sampled finding in twelve was real.

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
            default_enabled=False,
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
        # Files that configured ignore globs keep out of the report still call the project's symbols.
        used_names = _used_names([tree for _, tree in parsed_units] + list(context.reference_trees))
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
    """Collect the public top-level functions and classes of non-test units as candidates for the unreferenced check.

    Args:
        parsed_units: Each analysis unit paired with its parsed module tree; units that _is_test_unit classifies as test files contribute no
            candidates.

    Returns:
        Candidates in unit order and then module body order, one per top-level function, async function or class whose name does not start with an
        underscore; empty when none qualify.
    """
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
    """Match a unit's display path against test-file naming, so _export_candidates draws no candidates from it.

    Args:
        unit: Analysis unit whose display path is checked after backslashes are normalised to forward slashes.

    Returns:
        True when any directory segment of the path is exactly tests, or the file name starts with test_, ends with _test.py, or is conftest.py; False
        otherwise.
    """
    display_path = unit.file.display_path.replace("\\", "/")
    parts = display_path.split("/")
    name = parts[-1]
    return "tests" in parts[:-1] or name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def _used_names(trees: list[ast.Module]) -> set[str]:
    """Collect every name with a non-export reference anywhere in the project.

    Export plumbing deliberately does not count: ``__all__`` entries are
    string constants (never ``Name`` loads), and plain import aliases are
    skipped. Everything else - loads, attribute access, ``getattr`` string
    literals, aliased imports, and names inside quoted/forward-reference
    annotations - marks the name as used.

    Args:
        trees: Module trees to walk: the scanned units plus the context's reference trees from files kept out of the report.

    Returns:
        Every name that _node_references contributes from any node in any tree; a candidate whose name is missing from the set has no counted
        reference.
    """
    used: set[str] = set()
    for tree in trees:
        for node in ast.walk(tree):
            used.update(_node_references(node))
    return used


def _node_references(node: ast.AST) -> set[str]:
    """References a single node contributes (loads, attrs, imports, annotations).

    Args:
        node: One AST node visited by the project walk in _used_names.

    Returns:
        The id of a Name load, the attribute name of any Attribute node, the last dotted segment of each import name that has an alias (imports
        without an alias contribute nothing), the names _forward_reference_names finds in a function's return annotation or a parameter or annotated
        assignment annotation, or the second-argument string that _getattr_string_literal extracts from a bare getattr call; empty for any other node.
    """
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
    """Extract the string-literal attribute name passed to a bare getattr call, so that lookup counts as a reference.

    Args:
        node: AST node to test; only a call whose callee is the bare name getattr with at least two positional arguments qualifies.

    Returns:
        The string value of the second positional argument; None when the node is not such a call or that argument is not a string constant.
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr" and len(node.args) >= 2):
        return None
    literal = node.args[1]
    if isinstance(literal, ast.Constant) and isinstance(literal.value, str):
        return literal.value
    return None


def _forward_reference_names(annotation: ast.expr | None) -> set[str]:
    """Collect the names written inside string constants of an annotation, which the plain Name walk never sees.

    A fully quoted annotation (``-> "Payload"``) or a quoted element inside a generic (``list["Payload"]``) is a string constant, so each string
    constant found in the annotation is parsed by _names_in_expression. Unquoted names in the same annotation are not returned here; the project walk
    already counts them as Name loads.

    Args:
        annotation: Annotation expression to search, or None when the function has no return annotation or the parameter has no annotation.

    Returns:
        Names and attribute names parsed from every string constant in the annotation; empty when the annotation is None, contains no string constant,
        or none of its string constants parse.
    """
    if annotation is None:
        return set()
    names: set[str] = set()
    for node in ast.walk(annotation):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.update(_names_in_expression(node.value))
    return names


def _names_in_expression(text: str) -> set[str]:
    """Parse a quoted annotation string as an expression and collect the names and attribute names it mentions.

    Args:
        text: Value of a string constant taken from an annotation.

    Returns:
        The id of every Name node and the attribute name of every Attribute node in the parsed expression; empty when parsing the text raises
        SyntaxError.
    """
    try:
        parsed = ast.parse(text, mode="eval")
    except SyntaxError:
        return set()
    names: set[str] = set()
    for node in ast.walk(parsed):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            # ``"models.Payload"`` references ``Payload`` via the attribute, the
            # same way an unquoted ``models.Payload`` load would.
            names.add(node.attr)
    return names


def _is_exempt(
    candidate: _ExportCandidate,
    allowlist: DeadCodeAllowlist,
    entry_point_patterns: tuple[str, ...],
) -> bool:
    """Decide whether a framework decorator, the dead-code allowlist or an entry-point pattern exempts a candidate.

    Args:
        candidate: Public top-level definition with no counted reference.
        allowlist: The allowlists.deadCode config, matched against the candidate's display path, its name, and the name forms of its decorators from
            _decorator_name_forms; the decorator match is skipped when no decorator yields a name form.
        entry_point_patterns: Values of the rule's entryPointPatterns option, matched case-sensitively with fnmatch against the symbol name; empty
            disables this check.

    Returns:
        True when has_framework_decorator accepts the definition, the allowlist matches its display path, name or decorator name forms, or its name
        matches an entry-point pattern; False otherwise.
    """
    if has_framework_decorator(candidate.node):
        return True
    if allowlist.matches_path(candidate.unit.file.display_path):
        return True
    if allowlist.matches_symbol(candidate.name):
        return True
    decorator_names = tuple(name for decorator in candidate.node.decorator_list for name in _decorator_name_forms(decorator))
    if decorator_names and allowlist.matches_decorator(decorator_names):
        return True
    return any(fnmatch.fnmatchcase(candidate.name, pattern) for pattern in entry_point_patterns)


def _decorator_name_forms(decorator: ast.expr) -> tuple[str, ...]:
    """Derive the name forms of one decorator, unwrapping a call, for matching against the dead-code decorator allowlist.

    Args:
        decorator: Decorator expression; for a call such as ``@app.route("/")`` the callee is used instead.

    Returns:
        The dotted name joined from the attribute chain and its root name, plus the final segment alone when the dotted name has more than one segment
        (app.route gives app.route and route); a chain rooted in something other than a name contributes only its attribute segments; empty when the
        unwrapped expression is neither an attribute nor a name.
    """
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
    """Build the finding that reports a public function or class with no counted reference in the full-project scan.

    Args:
        definition: Rule definition whose id, default severity, pillar, tier, confidence and secondary pillars are copied onto the finding.
        candidate: Unreferenced, non-exempt public definition; its name, unit display path and node line span locate the finding.

    Returns:
        Finding at the candidate's display path spanning the definition node's start and end lines, with a message naming it as a public class or
        function, the fixed remediation text, its symbol field set to the candidate name, and metadata recording the symbol, kind and full-project
        scope.
    """
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
