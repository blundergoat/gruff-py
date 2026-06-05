"""``test-quality.static-analysis-redundant-test`` - assertions restating a same-file declaration.

Flags advisory candidates where a test's assertion verifies only a static source
declaration already visible in the same parsed module: that a local class exists
(``inspect.isclass``), or that one of its members is declared (``hasattr``,
``callable(getattr(...))``, or ``callable(Class.member)``). The wording is
"redundant candidate", never "delete this test".

Conservative and same-file only. The class operand must be a literal reference to
a ``class`` declared in this file, and a member must be a literal name resolving to
a class-body method or a real runtime attribute. Anything dynamic, imported,
instance-bound, private, or behavioural stays clean - it carries signal this rule
cannot prove redundant. Ports gruff-php's product semantics, not its AST mechanics:
Python ``hasattr`` reflects runtime attributes, so a bare annotation (``x: T`` with
no value) is not evidence, and private/dunder access stays with
``test-quality.private-reflection``.
"""

import ast
from dataclasses import dataclass, replace

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)

_DESCRIPTOR_DECORATORS = frozenset({"property", "cached_property", "setter", "deleter", "getter"})


@dataclass(frozen=True, slots=True)
class _ClassDecl:
    """A same-file class declaration and the members that exist on it at runtime.

    Attributes:
        qualified_name: Dotted same-file name (``Outer.Inner`` for nested classes).
        methods: Class-body method names, excluding ``@property``/descriptor methods.
        attributes: Class-body attribute names from assignments and annotated
            assignments that carry a value (bare annotations are excluded).
        nested: Directly class-body-declared nested classes, keyed by name.
        ambiguous_members: Class members whose runtime value was rebound or shadowed.
    """

    qualified_name: str
    methods: frozenset[str]
    attributes: frozenset[str]
    nested: dict[str, "_ClassDecl"]
    ambiguous_members: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _ShapeMatch:
    """A recognised redundant-assertion shape and the evidence that makes it redundant.

    Attributes:
        variant: Stable semantic variant id surfaced as ``metadata.variant``.
        helper: Assertion helper shown in the message (``hasattr``/``callable``/...).
        evidence_symbol: Source declaration the assertion restates (``Class.member``).
        static_fact: Human sentence naming the declaration visible in this file.
    """

    variant: str
    helper: str
    evidence_symbol: str
    static_fact: str


class StaticAnalysisRedundantTestRule(Rule):
    """Detect tests whose assertion only restates a class/member declared in the same file."""

    ID = "test-quality.static-analysis-redundant-test"

    def definition(self) -> RuleDefinition:
        """Describe the static-analysis-redundant-test rule as a high-confidence advisory.

        Advisory because an intentional public-API or compatibility contract can
        legitimately assert that a symbol exists; high confidence because the rule
        only fires on literal local-class evidence and biases to silence on any
        dynamic, imported, or behavioural shape.

        Returns:
            Definition tagging this rule under the test-quality pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Static-analysis-redundant test candidate",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
            description=(
                "Flags tests whose main assertion appears to verify only a static "
                "source declaration visible in the same parsed file."
            ),
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag assertions that verify only a same-file class or member declaration.

        Builds a declaration table of same-file classes, then scans each test body
        for the approved ``inspect.isclass`` / ``hasattr`` / ``callable`` shapes whose
        operands resolve to that table. Emits one candidate per redundant assertion.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One advisory finding per same-file-declaration-only assertion.
        """
        if unit.tree is None or not isinstance(unit.tree, ast.Module):
            return []
        classes, ambiguous = _build_class_table(unit.tree)
        if not classes:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            scoped_ambiguous = ambiguous | _local_rebindings(fn)
            for node in walk_test_body(fn):
                match = _match_assertion(node, classes, scoped_ambiguous)
                if match is not None:
                    findings.append(_finding(unit, definition, fn, node, match))
        return findings


def _build_class_table(module: ast.Module) -> tuple[dict[str, _ClassDecl], set[str]]:
    """Index top-level class declarations and names that shadow them.

    A name is ambiguous when an import, module-level function, or module-level
    non-class assignment binds it, so a same-named class can no longer be trusted
    as static evidence. A star import poisons the whole module (anything could be
    shadowed), so it returns no evidence at all.

    Args:
        module: Module AST to index.

    Returns:
        Mapping of class name to declaration, plus the set of ambiguous names.
    """
    classes: dict[str, _ClassDecl] = {}
    ambiguous: set[str] = set()
    for stmt in module.body:
        if isinstance(stmt, ast.ClassDef):
            classes[stmt.name] = _class_decl(stmt)
        elif isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            ambiguous.add(stmt.name)
        elif isinstance(stmt, ast.Import):
            ambiguous.update((alias.asname or alias.name).split(".")[0] for alias in stmt.names)
        elif isinstance(stmt, ast.ImportFrom):
            if any(alias.name == "*" for alias in stmt.names):
                return {}, set()
            ambiguous.update(alias.asname or alias.name for alias in stmt.names)
        elif isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                ambiguous.update(_bound_names(target))
                _mark_attribute_rebinding(classes, ambiguous, target)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            ambiguous.update(_bound_names(stmt.target))
        elif isinstance(stmt, ast.AnnAssign):
            _mark_attribute_rebinding(classes, ambiguous, stmt.target)
        elif isinstance(stmt, ast.AugAssign):
            ambiguous.update(_bound_names(stmt.target))
            _mark_attribute_rebinding(classes, ambiguous, stmt.target)
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                ambiguous.update(_bound_names(target))
                _mark_attribute_rebinding(classes, ambiguous, target)
    return classes, ambiguous


def _class_decl(node: ast.ClassDef, *, prefix: str = "") -> _ClassDecl:
    """Collect the runtime members declared directly in a class body.

    Methods exclude ``@property``/descriptor accessors; attributes include plain
    assignments and annotated assignments that carry a value, but not bare
    annotations (``x: T``), which create no runtime attribute.

    Args:
        node: Class definition to read.
        prefix: Dotted prefix for nested classes (``Outer.``).

    Returns:
        Declaration record for the class and any directly nested classes.
    """
    qualified = f"{prefix}{node.name}"
    methods: set[str] = set()
    attributes: set[str] = set()
    nested: dict[str, _ClassDecl] = {}
    binding_kinds: dict[str, set[str]] = {}
    attribute_rebinding_paths: list[tuple[str, ...]] = []
    for child in node.body:
        if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
            kind = "descriptor" if _is_descriptor_method(child) else "method"
            _record_binding(binding_kinds, child.name, kind)
            if not _is_descriptor_method(child):
                methods.add(child.name)
        elif isinstance(child, ast.ClassDef):
            _record_binding(binding_kinds, child.name, "nested")
            nested[child.name] = _class_decl(child, prefix=f"{qualified}.")
        elif isinstance(child, ast.Assign):
            for target in child.targets:
                for name in _bound_names(target):
                    attributes.add(name)
                    _record_binding(binding_kinds, name, "attribute")
                path = _attribute_path(target)
                if path:
                    attribute_rebinding_paths.append(path)
        elif (
            isinstance(child, ast.AnnAssign)
            and child.value is not None
            and isinstance(child.target, ast.Name)
        ):
            attributes.add(child.target.id)
            _record_binding(binding_kinds, child.target.id, "attribute")
        elif isinstance(child, ast.AnnAssign):
            path = _attribute_path(child.target)
            if path:
                attribute_rebinding_paths.append(path)
        elif isinstance(child, ast.AugAssign):
            for name in _bound_names(child.target):
                attributes.add(name)
                _record_binding(binding_kinds, name, "attribute")
            path = _attribute_path(child.target)
            if path:
                attribute_rebinding_paths.append(path)
        elif isinstance(child, ast.Delete):
            for target in child.targets:
                for name in _bound_names(target):
                    _record_binding(binding_kinds, name, "deleted")
                path = _attribute_path(target)
                if path:
                    attribute_rebinding_paths.append(path)
        elif isinstance(child, ast.Import | ast.ImportFrom):
            for name in _import_bound_names(child):
                _record_binding(binding_kinds, name, "import")
    ambiguous_members = frozenset(name for name, kinds in binding_kinds.items() if len(kinds) > 1)
    decl = _ClassDecl(
        qualified,
        frozenset(methods),
        frozenset(attributes),
        nested,
        ambiguous_members,
    )
    for path in attribute_rebinding_paths:
        if len(path) >= 2:
            decl = _with_ambiguous_member(decl, path[:-1], path[-1])
    return decl


def _record_binding(bindings: dict[str, set[str]], name: str, kind: str) -> None:
    """Record one class-body binding kind for ambiguity detection."""
    bindings.setdefault(name, set()).add(kind)


def _bound_names(target: ast.AST) -> set[str]:
    """Return names rebound by an assignment/delete target."""
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del)
    }


def _import_bound_names(node: ast.Import | ast.ImportFrom) -> set[str]:
    """Return local names bound by an import statement."""
    if isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            return set()
        return {alias.asname or alias.name for alias in node.names}
    return {(alias.asname or alias.name).split(".")[0] for alias in node.names}


def _attribute_path(target: ast.AST) -> tuple[str, ...]:
    """Return a dotted attribute assignment path such as ``Class.member``."""
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, ast.Attribute):
        prefix = _attribute_path(target.value)
        return (*prefix, target.attr) if prefix else ()
    return ()


def _mark_attribute_rebinding(
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
    target: ast.AST,
) -> None:
    """Mark ``Class.member`` assignment/delete targets as ambiguous evidence."""
    path = _attribute_path(target)
    if len(path) < 2 or path[0] in ambiguous:
        return
    decl = classes.get(path[0])
    if decl is None:
        return
    classes[path[0]] = _with_ambiguous_member(decl, path[1:-1], path[-1])


def _with_ambiguous_member(
    decl: _ClassDecl,
    owner_path: tuple[str, ...],
    member: str,
) -> _ClassDecl:
    """Return *decl* with a member marked ambiguous on the requested owner path."""
    if not owner_path:
        if member in decl.ambiguous_members:
            return decl
        return replace(decl, ambiguous_members=frozenset((*decl.ambiguous_members, member)))
    child_name = owner_path[0]
    if child_name in decl.ambiguous_members:
        return decl
    child = decl.nested.get(child_name)
    if child is None:
        return decl
    updated_child = _with_ambiguous_member(child, owner_path[1:], member)
    if updated_child == child:
        return decl
    nested = dict(decl.nested)
    nested[child_name] = updated_child
    return replace(decl, nested=nested)


def _local_rebindings(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return names rebound in the test function's local scope."""
    rebound: set[str] = set()
    for stmt in fn.body:
        for node in _walk_local_scope(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                rebound.add(node.id)
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                rebound.add(node.name)
            elif isinstance(node, ast.Import | ast.ImportFrom):
                rebound.update(_import_bound_names(node))
    return rebound


def _walk_local_scope(node: ast.AST) -> list[ast.AST]:
    """Walk a function body statement without entering nested scopes."""
    nodes = [node]
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
        return nodes
    for child in ast.iter_child_nodes(node):
        nodes.extend(_walk_local_scope(child))
    return nodes


def _is_descriptor_method(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a method is a property/descriptor accessor the rule defers."""
    return any(_decorator_leaf(dec) in _DESCRIPTOR_DECORATORS for dec in node.decorator_list)


def _decorator_leaf(decorator: ast.expr) -> str | None:
    """Return the trailing name of a decorator (``functools.cached_property`` -> ...)."""
    if isinstance(decorator, ast.Call):
        return _decorator_leaf(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        return decorator.attr
    return None


def _resolve_class(
    expr: ast.expr,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ClassDecl | None:
    """Resolve a class operand to a same-file declaration, or None when not local.

    Accepts a bare ``Name`` (top-level class) or an ``Outer.Inner`` attribute chain
    of nested classes. A name shadowed by an import or rebinding resolves to None.

    Args:
        expr: Operand expression naming the class.
        classes: Same-file class table.
        ambiguous: Names that cannot be trusted as class evidence.

    Returns:
        The resolved declaration, or None when the operand is not a local class.
    """
    if isinstance(expr, ast.Name):
        if expr.id in ambiguous:
            return None
        return classes.get(expr.id)
    if isinstance(expr, ast.Attribute):
        outer = _resolve_class(expr.value, classes, ambiguous)
        if outer is None or expr.attr in outer.ambiguous_members:
            return None
        return outer.nested.get(expr.attr)
    return None


def _match_assertion(
    node: ast.AST,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ShapeMatch | None:
    """Match a pytest ``assert`` or a unittest ``self.assertTrue(...)`` to a shape.

    Args:
        node: Body node visited inside a test function.
        classes: Same-file class table.
        ambiguous: Names that cannot be trusted as class evidence.

    Returns:
        The matched redundant-assertion shape, or None.
    """
    if isinstance(node, ast.Assert):
        return _candidate_for_shape(node.test, classes, ambiguous)
    if (
        isinstance(node, ast.Call)
        and call_target_name(node) == "self.assertTrue"
        and node.args
        and not isinstance(node.args[0], ast.Starred)
    ):
        return _candidate_for_shape(node.args[0], classes, ambiguous)
    return None


def _candidate_for_shape(
    expr: ast.expr,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ShapeMatch | None:
    """Dispatch an asserted expression to the matching approved-shape recogniser."""
    if not isinstance(expr, ast.Call):
        return None
    target = call_target_name(expr)
    if target == "inspect.isclass":
        return _isclass_candidate(expr, classes, ambiguous)
    if target == "hasattr":
        return _hasattr_candidate(expr, classes, ambiguous)
    if target == "callable":
        return _callable_candidate(expr, classes, ambiguous)
    return None


def _isclass_candidate(
    call: ast.Call,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ShapeMatch | None:
    """Recognise ``inspect.isclass(LocalClass)`` over a same-file class."""
    args = _plain_args(call, 1)
    if args is None:
        return None
    decl = _resolve_class(args[0], classes, ambiguous)
    if decl is None:
        return None
    return _ShapeMatch(
        "inspect-isclass",
        "inspect.isclass",
        decl.qualified_name,
        f"class {decl.qualified_name} is declared in the same parsed file",
    )


def _hasattr_candidate(
    call: ast.Call,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ShapeMatch | None:
    """Recognise ``hasattr(LocalClass, "member")`` over a declared method or attribute."""
    args = _plain_args(call, 2)
    if args is None:
        return None
    member = _string_value(args[1])
    if member is None:
        return None
    decl = _resolve_class(args[0], classes, ambiguous)
    if decl is None:
        return None
    kind = _member_kind(decl, member)
    if kind is None:
        return None
    evidence = f"{decl.qualified_name}.{member}"
    if kind == "method":
        return _ShapeMatch("hasattr-method", "hasattr", evidence, _method_fact(evidence))
    return _ShapeMatch(
        "hasattr-class-attribute",
        "hasattr",
        evidence,
        f"attribute {evidence} is declared in the same parsed file",
    )


def _callable_candidate(
    call: ast.Call,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ShapeMatch | None:
    """Recognise ``callable(getattr(C, "m"))`` and ``callable(C.m)`` over a declared method."""
    args = _plain_args(call, 1)
    if args is None:
        return None
    inner = args[0]
    if isinstance(inner, ast.Call) and call_target_name(inner) == "getattr":
        return _callable_method_match(inner, classes, ambiguous, "callable-getattr-method")
    if isinstance(inner, ast.Attribute):
        return _callable_attribute_match(inner, classes, ambiguous)
    return None


def _callable_method_match(
    getattr_call: ast.Call,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
    variant: str,
) -> _ShapeMatch | None:
    """Resolve ``getattr(LocalClass, "member")`` to a declared method, or None."""
    args = _plain_args(getattr_call, 2)
    if args is None:
        return None
    member = _string_value(args[1])
    if member is None:
        return None
    decl = _resolve_class(args[0], classes, ambiguous)
    if decl is None or _member_kind(decl, member) != "method":
        return None
    evidence = f"{decl.qualified_name}.{member}"
    return _ShapeMatch(variant, "callable", evidence, _method_fact(evidence))


def _callable_attribute_match(
    attribute: ast.Attribute,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
) -> _ShapeMatch | None:
    """Resolve ``LocalClass.member`` to a declared method, or None for non-methods."""
    decl = _resolve_class(attribute.value, classes, ambiguous)
    if decl is None or _member_kind(decl, attribute.attr) != "method":
        return None
    evidence = f"{decl.qualified_name}.{attribute.attr}"
    return _ShapeMatch("callable-attribute-method", "callable", evidence, _method_fact(evidence))


def _member_kind(decl: _ClassDecl, member: str) -> str | None:
    """Classify a member as ``method`` or ``classAttribute``, skipping private names.

    Private and dunder names (leading underscore) return None: that access is owned
    by ``test-quality.private-reflection``, so this rule never claims it.

    Args:
        decl: Resolved class declaration.
        member: Literal member name from the assertion.

    Returns:
        ``"method"``, ``"classAttribute"``, or None when not a public declared member.
    """
    if member.startswith("_"):
        return None
    if member in decl.ambiguous_members:
        return None
    if member in decl.methods:
        return "method"
    if member in decl.attributes:
        return "classAttribute"
    return None


def _plain_args(call: ast.Call, count: int) -> list[ast.expr] | None:
    """Return a call's positional args when there are exactly *count* and no keywords.

    Args:
        call: Call expression to inspect.
        count: Required number of positional arguments.

    Returns:
        The positional argument list, or None when the call shape does not match.
    """
    if call.keywords or len(call.args) != count:
        return None
    if any(isinstance(arg, ast.Starred) for arg in call.args):
        return None
    return call.args


def _string_value(node: ast.expr) -> str | None:
    """Return the value of a plain string-literal node, or None for anything dynamic."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _method_fact(evidence: str) -> str:
    """Render the static fact sentence for a declared-method assertion."""
    return f"method {evidence}() is declared in the same parsed file"


def _finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    node: ast.AST,
    match: _ShapeMatch,
) -> Finding:
    """Build the advisory candidate finding for one redundant assertion.

    Args:
        unit: Parsed source file the assertion lives in.
        definition: This rule's static metadata.
        fn: Test function or method containing the assertion.
        node: The ``assert`` statement or ``assertTrue`` call node.
        match: The recognised shape and its static evidence.

    Returns:
        The populated finding, carrying the cross-port metadata contract.
    """
    symbol = qualified_symbol(fn, parent_chain(fn))
    return Finding(
        rule_id=definition.id,
        message=(
            f"{symbol} contains a static-analysis-redundant candidate: "
            f"{match.helper} asserts {match.evidence_symbol}, but {match.static_fact}."
        ),
        file_path=unit.file.display_path,
        line=getattr(node, "lineno", None),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        symbol=symbol,
        remediation=(
            "Remove only the redundant assertion, or replace it with behavioral "
            "evidence that static analysis cannot prove."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "variant": match.variant,
            "assertion": ast.unparse(node),
            "staticFact": match.static_fact,
            "evidenceSymbol": match.evidence_symbol,
            "candidateConfidence": definition.confidence.value,
        },
    )
