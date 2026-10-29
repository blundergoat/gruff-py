"""``design.single-implementor-protocol`` - project-wide abstraction check.

Flags internal Protocol/ABC declarations that have exactly one explicit
subclass and no external annotation or value-position usage. The rule is
conservative on purpose: structural Protocol implementations are not inferred
in v0.1.
"""

import ast
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition

_ABSTRACTION_BASES: frozenset[str] = frozenset({"ABC", "ABCMeta", "Protocol"})
_EXTERNAL_PROTOCOL_BASES: tuple[str, ...] = (
    "Sized",
    "Iterable",
    "Iterator",
    "Collection",
    "Container",
    "Sequence",
    "Mapping",
    "MutableMapping",
    "Callable",
    "ContextManager",
    "AsyncContextManager",
)


@dataclass(frozen=True, slots=True)
class _ClassInfo:
    """Collected class declaration details used by the project-wide rule."""

    fqn: str
    simple_name: str
    unit: AnalysisUnit
    line: int
    bases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TypeReference:
    """Type annotation reference plus the class context that owns it."""

    name: str
    owner_class_fqn: str | None


class SingleImplementorProtocolRule:
    """Detect Protocol/ABC abstractions that only have one useful implementor."""

    ID = "design.single-implementor-protocol"

    def definition(self) -> RuleDefinition:
        """Return static metadata for the single-implementor abstraction rule.

        Returns:
            Rule metadata used by registry selection, configuration, and reports.
        """
        return RuleDefinition(
            id=self.ID,
            name="Single-implementor Protocol/ABC",
            pillar=Pillar.DESIGN,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={
                "externalProtocolBases": list(_EXTERNAL_PROTOCOL_BASES),
                "additionalExcludedPaths": [],
            },
        )

    def analyse_project(self, units: list[AnalysisUnit], context: RuleContext) -> list[Finding]:
        """Analyse the whole project for unnecessary abstractions.

        Args:
            units: Parsed project units to inspect together.
            context: Rule execution context with configured options.

        Returns:
            Findings for one-implementor abstractions without external type usage.
        """
        settings = context.settings_for(self.definition())
        external_bases = {base.lower() for base in settings.string_list_option("externalProtocolBases")}
        excluded_paths = tuple(settings.string_list_option("additionalExcludedPaths"))
        eligible_units = [unit for unit in units if unit.tree is not None and not _is_excluded(unit.file.display_path, excluded_paths)]
        classes = _collect_classes(eligible_units)
        abstractions = [info for info in classes if _is_internal_abstraction(info, external_bases)]
        abstraction_names = {info.fqn for info in abstractions} | {info.simple_name for info in abstractions}
        extended_abstractions = _extended_abstractions(abstractions, abstraction_names)
        references = _collect_type_references(eligible_units)
        return _findings_for_abstractions(
            abstractions=abstractions,
            extended_abstractions=extended_abstractions,
            classes=classes,
            external_bases=external_bases,
            references=references,
        )


def _findings_for_abstractions(
    *,
    abstractions: list[_ClassInfo],
    extended_abstractions: set[str],
    classes: list[_ClassInfo],
    external_bases: set[str],
    references: list[_TypeReference],
) -> list[Finding]:
    """Build a finding for each non-extended abstraction with exactly one implementor and no external references.

    Abstractions are visited in fqn order, so the findings come out sorted by the flagged abstraction's fqn.

    Args:
        abstractions: Internal abstractions collected from the eligible units.
        extended_abstractions: Base names through which one abstraction subclasses another; an abstraction matching one of them is skipped.
        classes: Every collected class, searched for the implementors of each abstraction.
        external_bases: Lowercased externalProtocolBases option values, used to keep internal abstractions out of the implementor search.
        references: Recorded annotation and value references, scanned to count external usage.

    Returns:
        Findings ordered by abstraction fqn; empty when no abstraction qualifies.
    """
    findings: list[Finding] = []
    for abstraction in sorted(abstractions, key=lambda item: item.fqn):
        if _is_extended_abstraction(abstraction, extended_abstractions):
            continue
        implementors = _implementors_for(abstraction, classes, external_bases)
        if len(implementors) != 1:
            continue
        implementor = implementors[0]
        external_usage_count = _external_usage_count(abstraction, implementor, references)
        if external_usage_count == 0:
            findings.append(_finding_for(abstraction, implementor, external_usage_count))
    return findings


def _is_extended_abstraction(abstraction: _ClassInfo, extended_abstractions: set[str]) -> bool:
    """Check whether the abstraction's fqn or simple name is among the base names that other abstractions extend.

    Args:
        abstraction: Abstraction to test.
        extended_abstractions: Dotted and last-segment base names collected by _extended_abstractions.

    Returns:
        True when the abstraction's fqn or simple name is in the set, which makes the caller skip it.
    """
    return abstraction.fqn in extended_abstractions or abstraction.simple_name in extended_abstractions


def _implementors_for(
    abstraction: _ClassInfo,
    classes: list[_ClassInfo],
    external_bases: set[str],
) -> list[_ClassInfo]:
    """Collect the classes that name the abstraction among their bases and are not internal abstractions themselves.

    Bases are matched by name with _is_matching_name, so structural Protocol implementations are not found, while a subclass of a same-named class
    from another module is.

    Args:
        abstraction: Abstraction whose implementors are wanted; the class itself is excluded by fqn.
        classes: Every collected class to search.
        external_bases: Lowercased externalProtocolBases option values, passed to _is_internal_abstraction to exclude other internal abstractions.

    Returns:
        Matching classes in collection order; the caller flags the abstraction only when exactly one is returned.
    """
    return [
        info
        for info in classes
        if info.fqn != abstraction.fqn
        and not _is_internal_abstraction(info, external_bases)
        and any(_is_matching_name(base, abstraction) for base in info.bases)
    ]


def _external_usage_count(
    abstraction: _ClassInfo,
    implementor: _ClassInfo,
    references: list[_TypeReference],
) -> int:
    """Count the references to an abstraction that are owned outside both the abstraction and its implementor.

    A reference's owner fqn is compared against the fqn and simple name of both classes; references recorded outside any class always count.

    Args:
        abstraction: Abstraction whose name each reference is matched against with _is_matching_name.
        implementor: Single implementor whose own references are ignored.
        references: Recorded annotation and value references to scan.

    Returns:
        Number of matching references with an outside owner; zero lets the caller flag the abstraction.
    """
    local_names = {
        abstraction.fqn,
        abstraction.simple_name,
        implementor.fqn,
        implementor.simple_name,
    }
    return sum(1 for reference in references if _is_matching_name(reference.name, abstraction) and reference.owner_class_fqn not in local_names)


def _finding_for(
    abstraction: _ClassInfo,
    implementor: _ClassInfo,
    external_usage_count: int,
) -> Finding:
    """Build the finding at the abstraction's class line that names the abstraction and its single implementor.

    Args:
        abstraction: Flagged abstraction whose file path, class line and fqn locate the finding.
        implementor: Single implementor, named in the message and the metadata.
        external_usage_count: External reference count written to the externalUsageCount metadata key and the decision text; the only caller passes
            zero.

    Returns:
        Finding carrying the rule's default severity, pillar, tier and confidence, with metadata keys protocolFqn, implementorCount (always 1),
        implementorFqn, externalUsageCount and decision.
    """
    definition = SingleImplementorProtocolRule().definition()
    return Finding(
        rule_id=definition.id,
        message=(
            f"Protocol/ABC {abstraction.fqn} has one implementor ({implementor.fqn}) "
            "and no external type-hint usage; consider depending on the class directly."
        ),
        file_path=abstraction.unit.file.display_path,
        line=abstraction.line,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        symbol=abstraction.fqn,
        remediation=(
            "Either delete the abstraction and depend on the concrete class, or add a "
            "second implementor / external type-hint usage that justifies it."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "protocolFqn": abstraction.fqn,
            "implementorCount": 1,
            "implementorFqn": implementor.fqn,
            "externalUsageCount": external_usage_count,
            "decision": f"flagged: 1 implementor, {external_usage_count} external usages",
        },
    )


def _is_excluded(display_path: str, excluded_paths: tuple[str, ...]) -> bool:
    """Check whether a display path starts with any configured additionalExcludedPaths prefix.

    The comparison is a plain string prefix match, with no glob syntax or path-segment boundary.

    Args:
        display_path: Display path of the unit being considered.
        excluded_paths: Prefixes from the additionalExcludedPaths option; an empty tuple excludes nothing.

    Returns:
        True when the path matches a prefix, which keeps the unit out of both class and reference collection.
    """
    return any(display_path.startswith(path) for path in excluded_paths)


def _is_internal_abstraction(info: _ClassInfo, external_bases: set[str]) -> bool:
    """Check whether a class directly subclasses ABC, ABCMeta or Protocol and has no external protocol base.

    Bases are compared by their last dotted segment: ABC, ABCMeta and Protocol match case-sensitively, the configured external bases
    case-insensitively.

    Args:
        info: Class whose base names are inspected.
        external_bases: Lowercased externalProtocolBases option values; any matching base disqualifies the class.

    Returns:
        True for an internal abstraction, False when no abstraction base is present or an external protocol base is.
    """
    base_leaves = {_leaf(base) for base in info.bases}
    if not (base_leaves & _ABSTRACTION_BASES):
        return False
    return not any(base.lower() in external_bases for base in base_leaves)


def _extended_abstractions(
    abstractions: list[_ClassInfo],
    abstraction_names: set[str],
) -> set[str]:
    """Collect the base names through which one abstraction subclasses another abstraction.

    Matching is by name only, so every abstraction sharing a simple name with an extended one is also treated as extended.

    Args:
        abstractions: Internal abstractions whose bases are scanned.
        abstraction_names: Fqns and simple names of all abstractions, matched against each base name and its last segment.

    Returns:
        Each matching base name in both its written and last-segment forms; empty when no abstraction extends another.
    """
    extended: set[str] = set()
    for abstraction in abstractions:
        for base in abstraction.bases:
            if base in abstraction_names or _leaf(base) in abstraction_names:
                extended.add(base)
                extended.add(_leaf(base))
    return extended


def _collect_classes(units: list[AnalysisUnit]) -> list[_ClassInfo]:
    """Collect module-level classes and the classes nested in their bodies from every unit with an ast.Module tree.

    Args:
        units: Eligible analysis units; a unit whose tree is not an ast.Module is skipped.

    Returns:
        Class infos in unit order, each class listed before the classes nested in it.
    """
    classes: list[_ClassInfo] = []
    for unit in units:
        if not isinstance(unit.tree, ast.Module):
            continue
        module = _module_name(unit)
        _collect_classes_from_body(unit, module, unit.tree.body, (), classes)
    return classes


def _collect_classes_from_body(
    unit: AnalysisUnit,
    module: str,
    body: list[ast.stmt],
    stack: tuple[str, ...],
    classes: list[_ClassInfo],
) -> None:
    """Append a class info for each class statement in a body, recursing into class bodies for nested classes.

    Only class statements sitting directly in the body are visited, so classes inside functions or if and try blocks are not collected. Base
    expressions with no name from _name_for are dropped.

    Args:
        unit: Analysis unit stored on each class info, which later supplies the finding's file path.
        module: Dotted module name prefixed to each fqn; empty for a top-level __init__ module, leaving the class names alone.
        body: Statements scanned for class definitions.
        stack: Names of the enclosing classes, empty at module level.
        classes: Output list this function appends to in place.
    """
    for stmt in body:
        if not isinstance(stmt, ast.ClassDef):
            continue
        class_stack = (*stack, stmt.name)
        fqn = ".".join((module, *class_stack)) if module else ".".join(class_stack)
        classes.append(
            _ClassInfo(
                fqn=fqn,
                simple_name=stmt.name,
                unit=unit,
                line=stmt.lineno,
                bases=tuple(_name_for(base) for base in stmt.bases if _name_for(base)),
            )
        )
        _collect_classes_from_body(unit, module, stmt.body, class_stack, classes)


def _collect_type_references(units: list[AnalysisUnit]) -> list[_TypeReference]:
    """Collect annotation names and loaded value names from every unit with an ast.Module tree via _ReferenceVisitor.

    The visitor does not visit class bases, so naming an abstraction as a base records no reference.

    Args:
        units: Eligible analysis units; a unit whose tree is not an ast.Module is skipped.

    Returns:
        One reference per recorded name, each carrying the fqn of its innermost enclosing class or None outside any class.
    """
    references: list[_TypeReference] = []
    for unit in units:
        if isinstance(unit.tree, ast.Module):
            _ReferenceVisitor(_module_name(unit), references).visit(unit.tree)
    return references


class _ReferenceVisitor(ast.NodeVisitor):
    """Collect annotation and value references while tracking the owning class."""

    def __init__(self, module: str, references: list[_TypeReference]) -> None:
        self.module = module
        self.references = references
        self.class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class without traversing nested owner state incorrectly.

        Args:
            node: Class definition node to inspect.
        """
        self.class_stack.append(node.name)
        for decorator in node.decorator_list:
            self.visit(decorator)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Record function annotations and then inspect its body.

        Args:
            node: Function definition node to inspect.
        """
        self._record_function_annotations(node)
        self._visit_function_defaults(node)
        for stmt in node.body:
            self.visit(stmt)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Record async function annotations and then inspect its body.

        Args:
            node: Async function definition node to inspect.
        """
        self._record_function_annotations(node)
        self._visit_function_defaults(node)
        for stmt in node.body:
            self.visit(stmt)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Record references from an annotated assignment.

        Args:
            node: Annotated assignment node to inspect.
        """
        self._record_annotation(node.annotation)
        if node.value is not None:
            self.visit(node.value)

    def visit_Name(self, node: ast.Name) -> None:
        """Record loaded names as value-position references.

        Args:
            node: Name expression node to inspect.
        """
        if isinstance(node.ctx, ast.Load):
            self._record_reference(node.id)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        """Record dotted value-position references.

        Only ``Load`` context counts, mirroring :meth:`visit_Name`: a store
        target such as ``module.Renderer = Fake`` (monkeypatching) binds an
        attribute *named* like the abstraction without referencing it. The
        loaded inner chain (``module``, or ``a.Renderer`` in
        ``a.Renderer.x = 1``) is still visited via ``generic_visit``.

        Args:
            node: Attribute expression node to inspect.
        """
        if isinstance(node.ctx, ast.Load):
            name = _name_for(node)
            if name:
                self._record_reference(name)
        self.generic_visit(node)

    def _record_function_annotations(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Record the names in every parameter annotation, variadic parameters included, and in the return annotation.

        Args:
            node: Function or async function definition whose annotations are read.
        """
        all_args = (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
            + ([node.args.vararg] if node.args.vararg is not None else [])
            + ([node.args.kwarg] if node.args.kwarg is not None else [])
        )
        for arg in all_args:
            if arg.annotation is not None:
                self._record_annotation(arg.annotation)
        if node.returns is not None:
            self._record_annotation(node.returns)

    def _visit_function_defaults(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit parameter default expressions so the names they load are recorded as references.

        Args:
            node: Function or async function definition whose positional and keyword-only defaults are visited; keyword-only parameters without a
                default are skipped.
        """
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)

    def _record_annotation(self, annotation: ast.AST) -> None:
        """Record each name extracted from an annotation expression as a reference, with the owner _owner_fqn reports.

        Args:
            annotation: Annotation expression; a node type without a handler in _ANNOTATION_NAME_HANDLERS records nothing.
        """
        for name in _annotation_names(annotation):
            self._record_reference(name)

    def _record_reference(self, name: str) -> None:
        """Append a reference for a name to the shared list, owned by the innermost enclosing class if there is one.

        Args:
            name: Bare or dotted name text to record.
        """
        self.references.append(_TypeReference(name=name, owner_class_fqn=self._owner_fqn()))

    def _owner_fqn(self) -> str | None:
        """Build the fqn of the innermost enclosing class, which owns any reference recorded at this point.

        Returns:
            Module name and class names joined by dots, the class names alone when the module name is empty, or None outside any class.
        """
        if not self.class_stack:
            return None
        return ".".join((self.module, *self.class_stack)) if self.module else ".".join(self.class_stack)


def _annotation_names(node: ast.AST) -> set[str]:
    """Extract the names an annotation expression mentions by dispatching on its exact node type.

    Args:
        node: Annotation expression or one of its sub-expressions.

    Returns:
        Extracted names; empty for a node type without a handler, such as a call.
    """
    handler = _ANNOTATION_NAME_HANDLERS.get(type(node))
    if handler is None:
        return set()
    return handler(node)


def _name_annotation_names(node: ast.AST) -> set[str]:
    """Return the identifier of a bare name in an annotation.

    Args:
        node: ast.Name node, as guaranteed by the handler table.

    Returns:
        One-element set holding the identifier.
    """
    assert isinstance(node, ast.Name)
    return {node.id}


def _attribute_names(node: ast.AST) -> set[str]:
    """Adapt _attribute_annotation_names to the ast.AST signature the annotation handler table expects.

    Args:
        node: ast.Attribute node, as guaranteed by the handler table.

    Returns:
        The attribute chain's dotted name and its last segment.
    """
    assert isinstance(node, ast.Attribute)
    return _attribute_annotation_names(node)


def _subscript_annotation_names(node: ast.AST) -> set[str]:
    """Extract names from both the subscripted value and its slice, such as list and Foo in ``list[Foo]``.

    Args:
        node: ast.Subscript node, as guaranteed by the handler table.

    Returns:
        Union of the names from the value and the slice.
    """
    assert isinstance(node, ast.Subscript)
    return _annotation_names(node.value) | _annotation_names(node.slice)


def _binop_annotation_names(node: ast.AST) -> set[str]:
    """Extract names from both operands of a binary operation, such as each member of an ``A | B`` union.

    Args:
        node: ast.BinOp node, as guaranteed by the handler table.

    Returns:
        Union of the names from the left and right operands.
    """
    assert isinstance(node, ast.BinOp)
    return _annotation_names(node.left) | _annotation_names(node.right)


def _tuple_annotation_names(node: ast.AST) -> set[str]:
    """Extract names from each tuple element, such as the key and value types in ``dict[K, V]``.

    Args:
        node: ast.Tuple node, as guaranteed by the handler table.

    Returns:
        Union of the names from every element.
    """
    assert isinstance(node, ast.Tuple)
    return _sequence_annotation_names(node.elts)


def _list_annotation_names(node: ast.AST) -> set[str]:
    """Extract names from each list element, such as the parameter types in ``Callable[[A], B]``.

    Args:
        node: ast.List node, as guaranteed by the handler table.

    Returns:
        Union of the names from every element.
    """
    assert isinstance(node, ast.List)
    return _sequence_annotation_names(node.elts)


def _constant_annotation_names(node: ast.AST) -> set[str]:
    """Return a string constant in an annotation as one name, treating it as a forward reference.

    The string is not parsed, so a quoted expression such as ``list[Foo]`` is kept whole and does not match Foo.

    Args:
        node: ast.Constant node, as guaranteed by the handler table.

    Returns:
        One-element set holding the string, or an empty set for a non-string constant such as None.
    """
    assert isinstance(node, ast.Constant)
    return {node.value} if isinstance(node.value, str) else set()


_ANNOTATION_NAME_HANDLERS = {
    ast.Name: _name_annotation_names,
    ast.Attribute: _attribute_names,
    ast.Subscript: _subscript_annotation_names,
    ast.BinOp: _binop_annotation_names,
    ast.Tuple: _tuple_annotation_names,
    ast.List: _list_annotation_names,
    ast.Constant: _constant_annotation_names,
}


def _attribute_annotation_names(node: ast.Attribute) -> set[str]:
    """Return an attribute chain's dotted name together with its last segment.

    Args:
        node: Attribute expression found in an annotation.

    Returns:
        Set holding the dotted name built by _name_for and its last segment.
    """
    name = _name_for(node)
    return {name, _leaf(name)} if name else set()


def _sequence_annotation_names(elements: list[ast.expr]) -> set[str]:
    """Union the annotation names extracted from each element of a tuple or list.

    Args:
        elements: Element expressions of the tuple or list.

    Returns:
        Union of the names from every element; empty for an empty sequence.
    """
    result: set[str] = set()
    for element in elements:
        result.update(_annotation_names(element))
    return result


def _is_matching_name(name: str, abstraction: _ClassInfo) -> bool:
    """Match a base or reference name to an abstraction by fqn, simple name or last dotted segment.

    No imports are resolved, so a same-named class from another module also matches.

    Args:
        name: Base name or reference name text.
        abstraction: Abstraction whose fqn and simple name are compared.

    Returns:
        True when the name equals the fqn or simple name, or its last segment equals the simple name.
    """
    return name in {abstraction.fqn, abstraction.simple_name} or _leaf(name) == abstraction.simple_name


def _name_for(node: ast.AST) -> str:
    """Build the dotted name text of a base or attribute expression, unwrapping subscripts and calls.

    A subscript yields its subscripted value, so ``Protocol[T]`` gives Protocol; a call yields its callee; a string constant is returned verbatim; an
    attribute whose prefix has no name yields only the attribute.

    Args:
        node: Expression to name.

    Returns:
        The bare or dotted name, or an empty string for any other node type.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _name_for(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        return _name_for(node.value)
    if isinstance(node, ast.Call):
        return _name_for(node.func)
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _leaf(name: str) -> str:
    """Return the last dot-separated segment of a name.

    Args:
        name: Bare or dotted name text.

    Returns:
        Text after the final dot, or the whole name when it contains no dot.
    """
    return name.rsplit(".", 1)[-1]


def _module_name(unit: AnalysisUnit) -> str:
    """Derive the dotted module name used as the fqn prefix from a unit's display path.

    Backslashes become slashes, the .py suffix and a trailing __init__ segment are dropped, and every remaining non-empty path segment becomes part of
    the name; no package root is detected.

    Args:
        unit: Analysis unit whose display path is converted.

    Returns:
        Dotted module name, or an empty string for a top-level __init__.py.
    """
    path = unit.file.display_path.replace("\\", "/")
    if path.endswith(".py"):
        path = path[:-3]
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    if path == "__init__":
        return ""
    return ".".join(part for part in path.split("/") if part)
