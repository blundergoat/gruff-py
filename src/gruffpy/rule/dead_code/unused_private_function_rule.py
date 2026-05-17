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
from collections.abc import Container
from dataclasses import dataclass

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


class UnusedPrivateFunctionRule(Rule):
    ID = "dead-code.unused-private-function"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unused private function",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        all_names = module_all_names(unit.tree)

        findings: list[Finding] = []
        for raw_node in ast.walk(unit.tree):
            candidate = _private_function_candidate(raw_node, unit.tree, all_names)
            if candidate is None:
                continue
            if _is_name_referenced_outside_def(
                candidate.node.name,
                candidate.scope,
                candidate.node,
            ) or _is_name_referenced_by_getattr(
                candidate.node.name, candidate.scope, candidate.node
            ):
                continue
            findings.append(_unused_private_function_finding(unit, definition, candidate))
        return findings


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
            "Delete the function or remove the leading underscore "
            "if external callers are expected."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"name": candidate.node.name},
    )


def _is_private(name: str) -> bool:
    return name.startswith("_")


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _is_name_referenced_outside_def(name: str, scope: ast.AST, defining_node: ast.AST) -> bool:
    """Return True if *name* appears as a Name/Attribute within *scope*
    anywhere except inside *defining_node* itself (which contains the name
    on its own ``name`` field — not a reference)."""
    for node in ast.walk(scope):
        if node is defining_node:
            continue
        if _is_descendant_of(node, defining_node):
            continue
        if isinstance(node, ast.Name) and node.id == name:
            return True
        if isinstance(node, ast.Attribute) and node.attr == name:
            return True
    return False


def _is_name_referenced_by_getattr(name: str, scope: ast.AST, defining_node: ast.AST) -> bool:
    for node in ast.walk(scope):
        if node is defining_node or _is_descendant_of(node, defining_node):
            continue
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "getattr":
            continue
        if len(node.args) < 2:
            continue
        if _does_getattr_name_match(name, node.args[1]):
            return True
    return False


def _does_getattr_name_match(name: str, value: ast.AST) -> bool:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value == name
    if isinstance(value, ast.JoinedStr):
        prefix = _joined_string_static_prefix(value)
        return len(prefix) >= 3 and name.startswith(prefix)
    return False


def _joined_string_static_prefix(value: ast.JoinedStr) -> str:
    prefix_parts: list[str] = []
    for part in value.values:
        if isinstance(part, ast.FormattedValue):
            break
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            prefix_parts.append(part.value)
    return "".join(prefix_parts)


def _is_descendant_of(node: ast.AST, ancestor: ast.AST) -> bool:
    current = getattr(node, "parent", None)
    while current is not None:
        if current is ancestor:
            return True
        current = getattr(current, "parent", None)
    return False
