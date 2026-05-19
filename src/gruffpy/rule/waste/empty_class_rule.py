"""Class whose body is ``pass`` or ``...`` only.

Skipped for: Protocol/ABC/TypedDict/Enum-like bases (they intentionally have
empty bodies as marker classes); for ``@dataclass``-decorated classes; and
for classes with decorators marked as framework hooks.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    _is_empty_body,
    has_dataclass_decorator,
    has_framework_base,
    has_framework_decorator,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class EmptyClassRule(Rule):
    """Detect classes with `pass`/`...` bodies outside Protocol/ABC/Enum/dataclass roles."""

    ID = "waste.empty-class"

    def definition(self) -> RuleDefinition:
        """Describe the empty-class rule as a high-confidence dead-code advisory.

        Advisory rather than warning because empty subclasses are sometimes
        a deliberate marker (custom exception types, namespacing). High
        confidence because ``pass``/``...``-only bodies are structurally
        unambiguous once the marker bases (Protocol, ABC, Enum, Exception)
        and dataclasses are exempted.

        Returns:
            Definition for the empty-class rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Empty class",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag classes whose entire body is ``pass`` or ``...``.

        Suppressed for dataclasses, framework decorators/bases, and marker
        bases (Protocol/ABC/Enum/Exception subclasses), where empty bodies
        are intentional.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per non-exempt class with an empty body.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [_empty_class_finding(unit, definition, node) for node in _empty_classes(unit.tree)]


def _empty_classes(tree: ast.AST) -> list[ast.ClassDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and _should_report_empty_class(node)
    ]


def _should_report_empty_class(node: ast.ClassDef) -> bool:
    if not _is_empty_body(node.body):
        return False
    return not (
        has_framework_base(node)
        or _is_marker_base_subclass(node)
        or has_dataclass_decorator(node)
        or has_framework_decorator(node)
    )


def _empty_class_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
) -> Finding:
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=f"Class {symbol!r} has an empty body.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=(
            "Delete the class, or implement it; if it's a marker base, extend Protocol/ABC."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )


def _is_marker_base_subclass(node: ast.ClassDef) -> bool:
    return bool(_base_names(node) & {"BaseException", "Exception", "Rule", "SourceTextRule"})


def _base_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for base in node.bases:
        name = _name_for(base)
        if name:
            names.add(name)
            names.add(name.split(".")[-1])
    return names


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
    return ""
