"""Private function/method never called in its enclosing scope.

A private function/method has a name starting with ``_`` (single underscore)
or ``__`` (double underscore — name-mangled). The rule scans the enclosing
scope (module for module-level functions, class for methods) and reports
when the name is never referenced.

Skip:

- names listed in ``__all__`` (intentional re-exports);
- dunder methods (``__init__``, ``__repr__``, etc.) — they ARE callable by
  the framework even when not explicitly referenced;
- abstract methods, overload stubs, Protocol method stubs;
- methods of classes extending a framework base (the protocol calls them);
- functions/methods carrying framework-hook decorators.

Confidence: MEDIUM. False positives are still possible on metaprogramming
(``getattr``, ``__getattr__``, plugin registries).
"""

import ast
from collections import Counter
from collections.abc import Container
from dataclasses import dataclass

from gruffpy.config.dead_code_allowlist import DeadCodeAllowlist
from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    has_framework_base,
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
    is_protocol_method_stub,
    module_all_names,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _PrivateFunctionCandidate:
    node: FunctionNode
    parents: list[ast.AST]
    scope: ast.AST


@dataclass(frozen=True, slots=True)
class _ReferenceCounts:
    names: Counter[str]
    attributes: Counter[str]
    getattr_names: Counter[str]
    getattr_prefixes: Counter[str]


class UnusedPrivateFunctionRule(Rule):
    ID = "dead-code.unused-private-function"

    def definition(self) -> RuleDefinition:
        """Describe the unused-private-function rule as a medium-confidence warning.

        Medium confidence: ``getattr``, plugin registries, and other
        metaprogramming patterns can call a private function in ways static
        analysis can't see.

        Returns:
            Definition for the unused-private-function rule under the
            dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unused private function",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``_``-prefixed functions/methods with no reference in their enclosing scope.

        Scope is the module for module-level functions and the class body
        for methods. References include ``Name`` reads, attribute access by
        bare name, and ``getattr(obj, "name")`` / f-string-prefix lookups
        for partial matches. The rule honours the project-level
        ``dead_code_allowlist`` so generated code or framework hooks can opt
        out by path, symbol, or decorator.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the allowlist.

        Returns:
            One finding per unreferenced private function or method.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        all_names = module_all_names(unit.tree)
        allowlist = context.config.dead_code_allowlist

        findings: list[Finding] = []
        scope_references: dict[int, _ReferenceCounts] = {}
        for raw_node in ast.walk(unit.tree):
            candidate = _private_function_candidate(raw_node, unit.tree, all_names)
            if candidate is None:
                continue
            scope_key = id(candidate.scope)
            references = scope_references.get(scope_key)
            if references is None:
                references = _collect_references(candidate.scope)
                scope_references[scope_key] = references
            own_references = _collect_references(candidate.node)
            if _has_external_reference(candidate.node.name, references, own_references):
                continue
            if _is_allowlisted(unit, candidate, allowlist):
                continue
            findings.append(_unused_private_function_finding(unit, definition, candidate))
        return findings


def _is_allowlisted(
    unit: AnalysisUnit,
    candidate: "_PrivateFunctionCandidate",
    allowlist: DeadCodeAllowlist,
) -> bool:
    if allowlist.matches_path(unit.file.display_path):
        return True
    symbol = qualified_symbol(candidate.node, candidate.parents)
    if allowlist.matches_symbol(symbol):
        return True
    return allowlist.matches_decorator(_decorator_names(candidate.node.decorator_list))


def _decorator_names(decorators: list[ast.expr]) -> tuple[str, ...]:
    names: list[str] = []
    for decorator in decorators:
        full = _decorator_repr(decorator)
        if not full:
            continue
        names.append(full)
        bare = full.rsplit(".", 1)[-1]
        if bare and bare != full:
            names.append(bare)
    return tuple(names)


def _decorator_repr(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _decorator_repr(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_repr(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""


def _private_function_candidate(
    node: ast.AST,
    tree: ast.AST,
    all_names: Container[str],
) -> _PrivateFunctionCandidate | None:
    if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return None

    parents = parent_chain(node)
    parent_cls = next((p for p in reversed(parents) if isinstance(p, ast.ClassDef)), None)
    if _should_skip_private_function(node, parents, parent_cls, all_names):
        return None

    return _PrivateFunctionCandidate(
        node=node,
        parents=parents,
        scope=parent_cls if parent_cls is not None else tree,
    )


def _should_skip_private_function(
    node: FunctionNode,
    parents: list[ast.AST],
    parent_cls: ast.ClassDef | None,
    all_names: Container[str],
) -> bool:
    return (
        not _is_private(node.name)
        or _is_dunder(node.name)
        or node.name in all_names
        or is_abstract_method(node)
        or is_overload_stub(node)
        or has_framework_decorator(node)
        or is_protocol_method_stub(node, parents)
        or (parent_cls is not None and has_framework_base(parent_cls))
    )


def _unused_private_function_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _PrivateFunctionCandidate,
) -> Finding:
    symbol = qualified_symbol(candidate.node, candidate.parents)
    return Finding(
        rule_id=definition.id,
        message=(f"Private function {symbol!r} is never called in its enclosing scope."),
        file_path=unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.node.end_lineno,
        symbol=symbol,
        remediation=(
            "Delete the function or remove the leading underscore if external callers are expected."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"name": candidate.node.name},
    )


def _is_private(name: str) -> bool:
    return name.startswith("_")


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _collect_references(root: ast.AST) -> _ReferenceCounts:
    references = _ReferenceCounts(
        names=Counter(),
        attributes=Counter(),
        getattr_names=Counter(),
        getattr_prefixes=Counter(),
    )
    for node in ast.walk(root):
        if isinstance(node, ast.Name):
            references.names[node.id] += 1
        elif isinstance(node, ast.Attribute):
            references.attributes[node.attr] += 1
        elif isinstance(node, ast.Call):
            _collect_getattr_reference(node, references)
    return references


def _collect_getattr_reference(node: ast.Call, references: _ReferenceCounts) -> None:
    if not isinstance(node.func, ast.Name) or node.func.id != "getattr":
        return
    if len(node.args) < 2:
        return
    name_arg = node.args[1]
    if isinstance(name_arg, ast.Constant) and isinstance(name_arg.value, str):
        references.getattr_names[name_arg.value] += 1
        return
    if isinstance(name_arg, ast.JoinedStr):
        prefix = _joined_string_static_prefix(name_arg)
        if len(prefix) >= 3:
            references.getattr_prefixes[prefix] += 1


def _has_external_reference(
    name: str,
    scope: _ReferenceCounts,
    defining_node: _ReferenceCounts,
) -> bool:
    if scope.names[name] > defining_node.names[name]:
        return True
    if scope.attributes[name] > defining_node.attributes[name]:
        return True
    if scope.getattr_names[name] > defining_node.getattr_names[name]:
        return True
    return any(
        name.startswith(prefix) and count > defining_node.getattr_prefixes[prefix]
        for prefix, count in scope.getattr_prefixes.items()
    )


def _joined_string_static_prefix(value: ast.JoinedStr) -> str:
    prefix_parts: list[str] = []
    for part in value.values:
        if isinstance(part, ast.FormattedValue):
            break
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            prefix_parts.append(part.value)
    return "".join(prefix_parts)
