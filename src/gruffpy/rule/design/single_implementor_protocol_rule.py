"""``design.single-implementor-protocol`` - project-wide abstraction check.

Flags internal Protocol/ABC declarations that have exactly one explicit
subclass and no external type-hint usage. The rule is conservative on purpose:
structural Protocol implementations are not inferred in v0.1.
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
    fqn: str
    simple_name: str
    unit: AnalysisUnit
    line: int
    bases: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _TypeReference:
    name: str
    owner_class_fqn: str | None


class SingleImplementorProtocolRule:
    """Detect Protocol/ABC abstractions that only have one useful implementor."""

    ID = "design.single-implementor-protocol"

    def definition(self) -> RuleDefinition:
        """Return rule metadata."""
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
        """Analyse the whole project for unnecessary abstractions."""
        settings = context.settings_for(self.definition())
        external_bases = {
            base.lower() for base in settings.string_list_option("externalProtocolBases")
        }
        excluded_paths = tuple(settings.string_list_option("additionalExcludedPaths"))
        eligible_units = [
            unit
            for unit in units
            if unit.tree is not None and not _is_excluded(unit.file.display_path, excluded_paths)
        ]
        classes = _collect_classes(eligible_units)
        abstractions = [info for info in classes if _is_internal_abstraction(info, external_bases)]
        abstraction_names = {info.fqn for info in abstractions} | {
            info.simple_name for info in abstractions
        }
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
    return (
        abstraction.fqn in extended_abstractions
        or abstraction.simple_name in extended_abstractions
    )


def _implementors_for(
    abstraction: _ClassInfo,
    classes: list[_ClassInfo],
    external_bases: set[str],
) -> list[_ClassInfo]:
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
    local_names = {
        abstraction.fqn,
        abstraction.simple_name,
        implementor.fqn,
        implementor.simple_name,
    }
    return sum(
        1
        for reference in references
        if _is_matching_name(reference.name, abstraction)
        and reference.owner_class_fqn not in local_names
    )


def _finding_for(
    abstraction: _ClassInfo,
    implementor: _ClassInfo,
    external_usage_count: int,
) -> Finding:
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
    return any(display_path.startswith(path) for path in excluded_paths)


def _is_internal_abstraction(info: _ClassInfo, external_bases: set[str]) -> bool:
    base_leaves = {_leaf(base) for base in info.bases}
    if not (base_leaves & _ABSTRACTION_BASES):
        return False
    return not any(base.lower() in external_bases for base in base_leaves)


def _extended_abstractions(
    abstractions: list[_ClassInfo],
    abstraction_names: set[str],
) -> set[str]:
    extended: set[str] = set()
    for abstraction in abstractions:
        for base in abstraction.bases:
            if base in abstraction_names or _leaf(base) in abstraction_names:
                extended.add(base)
                extended.add(_leaf(base))
    return extended


def _collect_classes(units: list[AnalysisUnit]) -> list[_ClassInfo]:
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
    references: list[_TypeReference] = []
    for unit in units:
        if isinstance(unit.tree, ast.Module):
            _AnnotationVisitor(_module_name(unit), references).visit(unit.tree)
    return references


class _AnnotationVisitor(ast.NodeVisitor):
    """Collect type annotation references while tracking the owning class."""

    def __init__(self, module: str, references: list[_TypeReference]) -> None:
        self.module = module
        self.references = references
        self.class_stack: list[str] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit a class without traversing nested owner state incorrectly."""
        self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Record function annotations and then inspect its body."""
        self._record_function_annotations(node)
        for stmt in node.body:
            self.visit(stmt)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Record async function annotations and then inspect its body."""
        self._record_function_annotations(node)
        for stmt in node.body:
            self.visit(stmt)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Record an annotated assignment."""
        self._record_annotation(node.annotation)
        self.generic_visit(node)

    def _record_function_annotations(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
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

    def _record_annotation(self, annotation: ast.AST) -> None:
        owner = self._owner_fqn()
        for name in _annotation_names(annotation):
            self.references.append(_TypeReference(name=name, owner_class_fqn=owner))

    def _owner_fqn(self) -> str | None:
        if not self.class_stack:
            return None
        return (
            ".".join((self.module, *self.class_stack))
            if self.module
            else ".".join(self.class_stack)
        )


def _annotation_names(node: ast.AST) -> set[str]:
    handler = _ANNOTATION_NAME_HANDLERS.get(type(node))
    if handler is None:
        return set()
    return handler(node)


def _name_annotation_names(node: ast.AST) -> set[str]:
    assert isinstance(node, ast.Name)
    return {node.id}


def _attribute_names(node: ast.AST) -> set[str]:
    assert isinstance(node, ast.Attribute)
    return _attribute_annotation_names(node)


def _subscript_annotation_names(node: ast.AST) -> set[str]:
    assert isinstance(node, ast.Subscript)
    return _annotation_names(node.value) | _annotation_names(node.slice)


def _binop_annotation_names(node: ast.AST) -> set[str]:
    assert isinstance(node, ast.BinOp)
    return _annotation_names(node.left) | _annotation_names(node.right)


def _tuple_annotation_names(node: ast.AST) -> set[str]:
    assert isinstance(node, ast.Tuple)
    return _sequence_annotation_names(node.elts)


def _list_annotation_names(node: ast.AST) -> set[str]:
    assert isinstance(node, ast.List)
    return _sequence_annotation_names(node.elts)


def _constant_annotation_names(node: ast.AST) -> set[str]:
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
    name = _name_for(node)
    return {name, _leaf(name)} if name else set()


def _sequence_annotation_names(elements: list[ast.expr]) -> set[str]:
    result: set[str] = set()
    for element in elements:
        result.update(_annotation_names(element))
    return result


def _is_matching_name(name: str, abstraction: _ClassInfo) -> bool:
    return (
        name in {abstraction.fqn, abstraction.simple_name}
        or _leaf(name) == abstraction.simple_name
    )


def _name_for(node: ast.AST) -> str:
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
    return name.rsplit(".", 1)[-1]


def _module_name(unit: AnalysisUnit) -> str:
    path = unit.file.display_path.replace("\\", "/")
    if path.endswith(".py"):
        path = path[:-3]
    if path.endswith("/__init__"):
        path = path[: -len("/__init__")]
    if path == "__init__":
        return ""
    return ".".join(part for part in path.split("/") if part)
