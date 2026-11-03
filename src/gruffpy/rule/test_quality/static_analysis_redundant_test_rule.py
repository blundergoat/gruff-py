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
from dataclasses import dataclass, field, replace

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


@dataclass(slots=True)
class _ClassParts:
    """Mutable accumulator used while reading one class body."""

    methods: set[str] = field(default_factory=set)
    attributes: set[str] = field(default_factory=set)
    nested: dict[str, _ClassDecl] = field(default_factory=dict)
    binding_kinds: dict[str, set[str]] = field(default_factory=dict)
    attribute_rebinding_paths: list[tuple[str, ...]] = field(default_factory=list)


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
            description=("Flags tests whose main assertion appears to verify only a static source declaration visible in the same parsed file."),
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
            local_shadows = _local_rebindings(fn)
            scoped_ambiguous = ambiguous | local_shadows
            for node in walk_test_body(fn):
                match = _match_assertion(node, classes, scoped_ambiguous, local_shadows)
                if match is not None:
                    findings.append(_finding(unit, definition, fn, node, match))
        return findings


def _build_class_table(module: ast.Module) -> tuple[dict[str, _ClassDecl], set[str]]:
    """Index top-level class declarations and names that shadow them.

    A name is ambiguous when an import, function, non-class assignment, ``del``,
    or ``Class.member`` write binds it anywhere in module-execution scope -
    including inside ``if``/``try``/``for``/``with`` bodies, where a conditional
    re-import or rebind still replaces the runtime object. Only classes declared
    directly at module top level, and not built dynamically by a decorator or
    metaclass, are trusted as static evidence. A star import anywhere in module
    scope poisons everything, so it returns no evidence at all.

    Args:
        module: Module AST to index.

    Returns:
        Mapping of class name to declaration, plus the set of ambiguous names.
    """
    classes: dict[str, _ClassDecl] = {}
    for stmt in module.body:
        if isinstance(stmt, ast.ClassDef) and not _is_dynamic_class(stmt):
            classes[stmt.name] = _class_decl(stmt)
    ambiguous: set[str] = set()
    for stmt in _module_scope_statements(module.body):
        if _is_star_import(stmt):
            return {}, set()
        if isinstance(stmt, ast.ClassDef):
            if _is_dynamic_class(stmt):
                ambiguous.add(stmt.name)
            continue
        ambiguous.update(_module_bound_names(stmt))
        for target in _statement_targets(stmt):
            _mark_attribute_rebinding(classes, ambiguous, target)
    return classes, ambiguous


def _module_scope_statements(body: list[ast.stmt]) -> list[ast.stmt]:
    """Return statements executed in module scope, descending compound bodies.

    Recurses into ``if``/``for``/``while``/``with``/``try`` bodies and ``match``
    case bodies (a binding there still shadows a module-level class) but never
    into nested function, class, or lambda scopes.

    Args:
        body: Statement list to flatten.

    Returns:
        Every module-scope statement, compound-statement bodies included.
    """
    stmts: list[ast.stmt] = []
    for stmt in body:
        stmts.append(stmt)
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            continue
        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.stmt):
                stmts.extend(_module_scope_statements([child]))
            elif isinstance(child, ast.ExceptHandler | ast.match_case):
                stmts.extend(_module_scope_statements(child.body))
    return stmts


def _is_dynamic_class(node: ast.ClassDef) -> bool:
    """Return whether a class is built dynamically by a decorator or metaclass.

    A class decorator or metaclass can add, remove, or replace members at class
    creation, so the parsed body is no longer proof of the runtime shape and the
    class must not be trusted as static evidence.

    Args:
        node: Class definition to inspect.

    Returns:
        True when the class carries a decorator or a ``metaclass=`` keyword.
    """
    if node.decorator_list:
        return True
    return any(keyword.arg == "metaclass" for keyword in node.keywords)


def _is_star_import(stmt: ast.stmt) -> bool:
    """Return whether a module statement is a star import.

    Args:
        stmt: Module-scope statement to check for an import-from wildcard.

    Returns:
        True for an import-from statement containing a wildcard alias; false for other statements.
    """
    return isinstance(stmt, ast.ImportFrom) and any(alias.name == "*" for alias in stmt.names)


def _module_bound_names(stmt: ast.stmt) -> set[str]:
    """Return top-level names that make same-name class evidence ambiguous.

    Args:
        stmt: Statement visited in module execution scope whose bindings may shadow class evidence.

    Returns:
        Names bound or deleted by the supported statement shape; empty when it contributes no names.
    """
    if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
        return {stmt.name}
    if isinstance(stmt, ast.Import | ast.ImportFrom):
        return _import_bound_names(stmt)
    if isinstance(stmt, ast.Match):
        return _match_capture_names(stmt)
    return _targets_bound_names(_statement_targets(stmt))


def _match_capture_names(match: ast.Match) -> set[str]:
    """Return names bound by capture patterns across every ``match`` case.

    A bare-name pattern such as ``case Widget:`` is a capture, not a value
    match: it rebinds ``Widget`` to the subject rather than comparing against
    the existing class, so the same-file class can no longer be trusted.

    Args:
        match: Match statement whose case patterns are inspected for capture bindings.

    Returns:
        Distinct names captured by the case patterns, including star and mapping-rest captures; empty when none are named.
    """
    names: set[str] = set()
    for case in match.cases:
        for node in ast.walk(case.pattern):
            name = _capture_name(node)
            if name is not None:
                names.add(name)
    return names


def _capture_name(node: ast.AST) -> str | None:
    """Return the name a structural-pattern node binds, or None when it binds nothing.

    Args:
        node: Pattern node to inspect for a named capture or mapping-rest binding.

    Returns:
        The captured name, or None for an unnamed capture or a node without a supported binding.
    """
    if isinstance(node, ast.MatchAs | ast.MatchStar):
        return node.name
    if isinstance(node, ast.MatchMapping):
        return node.rest
    return None


def _statement_targets(stmt: ast.stmt) -> tuple[ast.expr, ...]:
    """Return assignment/delete targets from a statement, or empty for other statements.

    Args:
        stmt: Statement whose assignment, augmented-assignment or deletion targets are needed.

    Returns:
        The original target nodes for supported assignments or deletions; an empty tuple for other statements.
    """
    if isinstance(stmt, ast.Assign):
        return tuple(stmt.targets)
    if isinstance(stmt, ast.AnnAssign | ast.AugAssign):
        return (stmt.target,)
    if isinstance(stmt, ast.Delete):
        return tuple(stmt.targets)
    return ()


def _targets_bound_names(targets: tuple[ast.expr, ...]) -> set[str]:
    """Return every name bound by a sequence of assignment/delete targets.

    Args:
        targets: Assignment or deletion target nodes whose stored/deleted names are combined.

    Returns:
        Distinct stored or deleted names found within the supplied targets; empty when none occur.
    """
    bound: set[str] = set()
    for target in targets:
        bound.update(_bound_names(target))
    return bound


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
    parts = _ClassParts()
    for child in node.body:
        _collect_class_child(child, parts, qualified)
    return _class_decl_from_parts(qualified, parts)


def _collect_class_child(child: ast.stmt, parts: _ClassParts, qualified: str) -> None:
    """Collect one class-body statement into *parts*.

    Args:
        child: Direct class-body statement to classify as a declaration, import or binding effect.
        parts: Accumulator mutated with collected members, binding kinds and attribute-rebinding paths.
        qualified: Qualified name of the containing class, used to prefix nested declarations.
    """
    if isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef):
        _collect_class_method(child, parts)
        return
    if isinstance(child, ast.ClassDef):
        _collect_nested_class(child, parts, qualified)
        return
    if isinstance(child, ast.Import | ast.ImportFrom):
        _collect_class_import(child, parts)
        return
    if _is_compound_statement(child):
        _record_conditional_class_bindings(child, parts)
        return
    _collect_class_statement_bindings(child, parts)


def _collect_class_method(
    child: ast.FunctionDef | ast.AsyncFunctionDef,
    parts: _ClassParts,
) -> None:
    """Collect a method declaration or descriptor accessor.

    Args:
        child: Direct method declaration whose decorator spellings determine descriptor treatment.
        parts: Accumulator mutated with the binding kind and, for a non-descriptor method, its method name.
    """
    is_descriptor = _is_descriptor_method(child)
    kind = "descriptor" if is_descriptor else "method"
    _record_binding(parts.binding_kinds, child.name, kind)
    if not is_descriptor:
        parts.methods.add(child.name)


def _collect_nested_class(child: ast.ClassDef, parts: _ClassParts, qualified: str) -> None:
    """Collect a direct nested class declaration.

    A decorator or metaclass on the nested class makes its runtime shape dynamic,
    so it is recorded as an ambiguous member rather than trusted evidence.

    Args:
        child: Direct nested class to collect, including its dynamic-class binding marker when applicable.
        parts: Accumulator mutated with the nested declaration and its binding kinds.
        qualified: Qualified name of the containing class, used as the nested declaration prefix.
    """
    _record_binding(parts.binding_kinds, child.name, "nested")
    if _is_dynamic_class(child):
        _record_binding(parts.binding_kinds, child.name, "dynamic")
    parts.nested[child.name] = _class_decl(child, prefix=f"{qualified}.")


def _collect_class_import(node: ast.Import | ast.ImportFrom, parts: _ClassParts) -> None:
    """Collect names bound by a class-body import.

    Args:
        node: Class-body import whose locally bound names are recorded; wildcard imports contribute no names.
        parts: Accumulator whose binding-kind sets are extended with import bindings.
    """
    for name in _import_bound_names(node):
        _record_binding(parts.binding_kinds, name, "import")


def _collect_class_statement_bindings(stmt: ast.stmt, parts: _ClassParts) -> None:
    """Collect assignment/delete effects from a class-body statement.

    Args:
        stmt: Class-body statement to inspect for assignment/delete targets and binding kinds.
        parts: Accumulator mutated with attribute names, binding kinds and dotted rebinding paths from supported targets.
    """
    binding_kind = _class_name_binding_kind(stmt)
    for target in _statement_targets(stmt):
        if binding_kind is not None:
            _collect_class_name_bindings(target, binding_kind, parts)
        _collect_attribute_rebinding_path(target, parts)


def _is_compound_statement(stmt: ast.stmt) -> bool:
    """Return whether a class-body statement has nested bodies the class scope runs.

    Args:
        stmt: Class-body statement to check against the supported compound-statement types.

    Returns:
        True for a supported conditional, loop, with, try or match statement; false for other statement types.
    """
    return isinstance(
        stmt,
        ast.If | ast.For | ast.AsyncFor | ast.While | ast.With | ast.AsyncWith | ast.Try | ast.TryStar | ast.Match,
    )


def _record_conditional_class_bindings(stmt: ast.stmt, parts: _ClassParts) -> None:
    """Mark members conditionally rebound inside a class-body compound as ambiguous.

    A member declared at the class top level but also assigned, deleted,
    imported, redefined, or pattern-captured inside an ``if``/``for``/``while``/
    ``with``/``try``/``match`` body is no longer statically known, so each such
    binding is recorded to poison that member as evidence. The conditional
    binding is never added to the trusted method/attribute sets, and nested
    function and class scopes are not entered - their members are collected on
    their own. Mirrors the module-scope descent in ``_module_scope_statements``.

    Args:
        stmt: Compound class-body statement whose subtree is inspected without descending into nested scopes.
        parts: Accumulator mutated with conditional binding markers and dotted attribute-rebinding paths.
    """
    for node in _walk_local_scope(stmt):
        for name in _conditional_bound_names(node):
            _record_binding(parts.binding_kinds, name, "conditional")
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store | ast.Del):
            _collect_attribute_rebinding_path(node, parts)


def _conditional_bound_names(node: ast.AST) -> set[str]:
    """Return names a single node binds inside a conditional class-body subtree.

    Args:
        node: One visited node in a conditional class-body subtree, rather than the whole subtree.

    Returns:
        Names bound or deleted by this node, including declaration, import, exception and pattern captures; empty otherwise.
    """
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
        return {node.id}
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        return {node.name}
    if isinstance(node, ast.Import | ast.ImportFrom):
        return _import_bound_names(node)
    if isinstance(node, ast.ExceptHandler) and node.name is not None:
        return {node.name}
    capture = _capture_name(node)
    return {capture} if capture is not None else set()


def _class_name_binding_kind(stmt: ast.stmt) -> str | None:
    """Return the class-body binding kind for names in *stmt*.

    Args:
        stmt: Class-body statement whose assignment or deletion syntax is classified.

    Returns:
        The attribute kind for an assignment carrying a value, the deleted kind for a deletion, or None for other statements.
    """
    if isinstance(stmt, ast.Assign | ast.AugAssign):
        return "attribute"
    if isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
        return "attribute"
    if isinstance(stmt, ast.Delete):
        return "deleted"
    return None


def _collect_class_name_bindings(target: ast.expr, kind: str, parts: _ClassParts) -> None:
    """Collect names introduced or removed by one class-body target.

    Args:
        target: Assignment/delete target whose stored or deleted names are collected.
        kind: Binding category to record; the attribute category also adds names to the attribute set.
        parts: Accumulator mutated with binding kinds and any attribute evidence contributed by the target.
    """
    for name in _bound_names(target):
        if kind == "attribute":
            parts.attributes.add(name)
        _record_binding(parts.binding_kinds, name, kind)


def _collect_attribute_rebinding_path(target: ast.expr, parts: _ClassParts) -> None:
    """Remember dotted member writes/deletes for later ambiguity marking.

    Args:
        target: Assignment/delete target; only attribute chains rooted in a name are recorded.
        parts: Accumulator whose rebinding-path list receives the dotted target when it has at least two components.
    """
    path = _attribute_path(target)
    if len(path) >= 2:
        parts.attribute_rebinding_paths.append(path)


def _class_decl_from_parts(qualified: str, parts: _ClassParts) -> _ClassDecl:
    """Build a class declaration from collected members and binding effects.

    Args:
        qualified: Qualified name to place on the resulting declaration.
        parts: Collected member and binding data to read; its nested mapping is reused unless a rebinding requires a copied path.

    Returns:
        A frozen declaration with member-name snapshots and ambiguity markers, plus the retained or path-copied nested mapping.
    """
    ambiguous_members = frozenset(name for name, kinds in parts.binding_kinds.items() if len(kinds) > 1)
    decl = _ClassDecl(
        qualified,
        frozenset(parts.methods),
        frozenset(parts.attributes),
        parts.nested,
        ambiguous_members,
    )
    for path in parts.attribute_rebinding_paths:
        decl = _with_ambiguous_member(decl, path[:-1], path[-1])
    return decl


def _record_binding(bindings: dict[str, set[str]], name: str, kind: str) -> None:
    """Record one class-body binding kind for ambiguity detection.

    Args:
        bindings: Mapping mutated by creating the name entry if needed and adding the binding category.
        name: Local class-member name whose binding category is being recorded.
        kind: Binding category added to the name's set for later ambiguity detection.
    """
    bindings.setdefault(name, set()).add(kind)


def _bound_names(target: ast.AST) -> set[str]:
    """Return names rebound by an assignment/delete target.

    Args:
        target: Assignment/delete target subtree to inspect for names with Store or Del context.

    Returns:
        Distinct stored or deleted names in the target subtree; empty when it contains none.
    """
    return {node.id for node in ast.walk(target) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del)}


def _import_bound_names(node: ast.Import | ast.ImportFrom) -> set[str]:
    """Return local names bound by an import statement.

    Args:
        node: Import statement whose aliases or imported names determine local bindings.

    Returns:
        Local import names, using the root name for unaliased ordinary imports; an empty set for wildcard import-from statements.
    """
    if isinstance(node, ast.ImportFrom):
        if any(alias.name == "*" for alias in node.names):
            return set()
        return {alias.asname or alias.name for alias in node.names}
    return {(alias.asname or alias.name).split(".")[0] for alias in node.names}


def _attribute_path(target: ast.AST) -> tuple[str, ...]:
    """Return a dotted attribute assignment path such as ``Class.member``.

    Args:
        target: Name or attribute-chain target to decompose without evaluating its receiver.

    Returns:
        Name components from root to leaf, including a one-component bare name; empty when the chain has no named root.
    """
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
    """Mark ``Class.member`` assignment/delete targets as ambiguous evidence.

    Args:
        classes: Class table whose root declaration may be replaced with one carrying an ambiguous-member marker.
        ambiguous: Root names excluded from trusted evidence; this set is consulted without mutation.
        target: Assignment/delete target to resolve as a name-rooted member path in the class table.
    """
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
    """Return *decl* with a member marked ambiguous on the requested owner path.

    Args:
        decl: Declaration to read without mutating its fields or nested mappings.
        owner_path: Nested-class path locating the member owner; empty means the supplied declaration itself.
        member: Member name to mark ambiguous on the resolved owner.

    Returns:
        The original declaration for an unavailable or already-marked path; otherwise a replacement with copied mappings along the changed path.
    """
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
    """Return names rebound in the test function's local scope.

    Covers the function's own parameters (a fixture or parametrized argument that
    shares a class name resolves to the parameter, not the class) and the root of
    any ``Class.member`` write or delete in the body (an in-test monkeypatch makes
    the member a runtime mutation, not a static declaration), alongside local name
    binds, nested defs/classes, and imports.

    Args:
        fn: Test function whose signature and body are inspected for supported local bindings and attribute writes.

    Returns:
        Names from the parameters and supported body bindings or attribute-write roots, without descending into nested scope bodies.
    """
    rebound: set[str] = _parameter_names(fn)
    for stmt in fn.body:
        for node in _walk_local_scope(stmt):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                rebound.add(node.id)
            elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store | ast.Del):
                path = _attribute_path(node)
                if path:
                    rebound.add(path[0])
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                rebound.add(node.name)
            elif isinstance(node, ast.Import | ast.ImportFrom):
                rebound.update(_import_bound_names(node))
    return rebound


def _parameter_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return every parameter name bound by a test function's signature.

    Args:
        fn: Function whose positional, keyword-only and variadic parameter names are collected.

    Returns:
        All declared parameter names, including variadic names; an empty set for a parameterless function.
    """
    args = fn.args
    names = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _walk_local_scope(node: ast.AST) -> list[ast.AST]:
    """Walk a function body statement without entering nested scopes.

    Args:
        node: Root node to include, visiting descendants except inside function, lambda and class boundaries.

    Returns:
        Nodes in preorder, including encountered scope-boundary nodes but none of their children.
    """
    nodes = [node]
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
        return nodes
    for child in ast.iter_child_nodes(node):
        nodes.extend(_walk_local_scope(child))
    return nodes


def _is_descriptor_method(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return whether a method is a property/descriptor accessor the rule defers.

    Args:
        node: Method whose decorator leaf spellings are checked against the configured descriptor names.

    Returns:
        True when a decorator leaf matches a recognized descriptor spelling; false otherwise, without resolving imports.
    """
    return any(_decorator_leaf(dec) in _DESCRIPTOR_DECORATORS for dec in node.decorator_list)


def _decorator_leaf(decorator: ast.expr) -> str | None:
    """Return the trailing name of a decorator (``functools.cached_property`` -> ...).

    Args:
        decorator: Decorator expression whose terminal name is extracted after unwrapping calls.

    Returns:
        The bare name or final attribute component, or None when the expression has no supported name form.
    """
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
    local_shadows: set[str],
) -> _ShapeMatch | None:
    """Match a pytest ``assert`` or a unittest ``self.assertTrue(...)`` to a shape.

    Args:
        node: Body node visited inside a test function.
        classes: Same-file class table.
        ambiguous: Names that cannot be trusted as class evidence.
        local_shadows: Names rebound in the test's local scope (params + body).

    Returns:
        The matched redundant-assertion shape, or None.
    """
    if isinstance(node, ast.Assert):
        return _candidate_for_shape(node.test, classes, ambiguous, local_shadows)
    if isinstance(node, ast.Call) and call_target_name(node) == "self.assertTrue" and node.args and not isinstance(node.args[0], ast.Starred):
        return _candidate_for_shape(node.args[0], classes, ambiguous, local_shadows)
    return None


def _candidate_for_shape(
    expr: ast.expr,
    classes: dict[str, _ClassDecl],
    ambiguous: set[str],
    local_shadows: set[str],
) -> _ShapeMatch | None:
    """Dispatch an asserted expression to the matching approved-shape recogniser.

    Skips the assertion when the helper itself (``hasattr``/``callable``/the
    ``inspect`` module) is rebound in the test's local scope, since the call no
    longer resolves to the builtin or stdlib helper the rule reasons about.

    Args:
        expr: Asserted expression to dispatch only when it is a recognized call shape.
        classes: Same-file class declarations used to resolve the candidate operand.
        ambiguous: Names excluded from trusted class evidence because they are shadowed or rebound.
        local_shadows: Local bindings used to reject an asserted call whose helper root is shadowed.

    Returns:
        The match from a supported shape recognizer, or None for an unsupported, shadowed or unresolved candidate.
    """
    if not isinstance(expr, ast.Call):
        return None
    target = call_target_name(expr)
    if target is None or target.split(".")[0] in local_shadows:
        return None
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
    """Recognise ``inspect.isclass(LocalClass)`` over a same-file class.

    Args:
        call: Candidate call already identified as inspect.isclass, whose single plain argument is checked.
        classes: Same-file declarations used to resolve a bare or nested-class operand.
        ambiguous: Names excluded from trusted class evidence during operand resolution.

    Returns:
        A class-declaration match, or None when the arguments or class operand do not provide supported evidence.
    """
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
    """Recognise ``hasattr(LocalClass, "member")`` over a declared method or attribute.

    Args:
        call: Candidate hasattr call checked for two plain arguments and a literal member name.
        classes: Same-file declarations used to resolve the class operand.
        ambiguous: Names excluded from trusted class evidence during operand resolution.

    Returns:
        A declared public method or attribute match, or None for unsupported arguments, unresolved classes or ineligible members.
    """
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
    """Recognise ``callable(getattr(C, "m"))`` and ``callable(C.m)`` over a declared method.

    Args:
        call: Candidate callable call checked for one plain getattr call or attribute-access argument.
        classes: Same-file declarations used to resolve the inner class operand.
        ambiguous: Names excluded from trusted class evidence during operand resolution.

    Returns:
        A declared-method match from the supported inner shape, or None when that shape or its evidence is ineligible.
    """
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
    """Resolve ``getattr(LocalClass, "member")`` to a declared method, or None.

    Args:
        getattr_call: Inner getattr call checked for two plain arguments, including a literal member name.
        classes: Same-file declarations used to resolve the class operand.
        ambiguous: Names excluded from trusted class evidence during operand resolution.
        variant: Variant identifier to carry unchanged in the returned match.

    Returns:
        A match for a declared public, unambiguous method; None for unsupported arguments, unresolved classes or other members.
    """
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
    """Resolve ``LocalClass.member`` to a declared method, or None for non-methods.

    Args:
        attribute: Attribute access whose receiver is resolved as a same-file class and whose leaf names the method.
        classes: Same-file declarations used to resolve the receiver.
        ambiguous: Names excluded from trusted class evidence during receiver resolution.

    Returns:
        A callable-attribute match for a declared public, unambiguous method, or None when that evidence is unavailable.
    """
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
    """Return the value of a plain string-literal node, or None for anything dynamic.

    Args:
        node: Argument expression to accept only when it is a string-valued Constant node.

    Returns:
        The literal string value, including an empty string, or None for other expression forms or constant types.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _method_fact(evidence: str) -> str:
    """Render the static fact sentence for a declared-method assertion.

    Args:
        evidence: Qualified method name inserted into the fact sentence; the caller has already selected its declaration evidence.

    Returns:
        A sentence stating that the named method is declared in the same parsed file.
    """
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
            f"{symbol} contains a static-analysis-redundant candidate: {match.helper} asserts {match.evidence_symbol}, but {match.static_fact}."
        ),
        file_path=unit.file.display_path,
        line=getattr(node, "lineno", None),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        symbol=symbol,
        remediation=("Remove only the redundant assertion, or replace it with behavioral evidence that static analysis cannot prove."),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "variant": match.variant,
            "assertion": ast.unparse(node),
            "staticFact": match.static_fact,
            "evidenceSymbol": match.evidence_symbol,
            "candidateConfidence": definition.confidence.value,
        },
    )
