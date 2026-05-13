"""``self._x`` assigned in a class but never read anywhere in the class body.

Skip:

- dataclass field declarations (``@dataclass`` class with annotated fields);
- ``@property`` backing fields (``self._x`` paired with ``@property`` getter
  named ``x``);
- classes extending ABC/Protocol (framework hooks);
- name-mangled attributes that the body accesses with the mangled form
  (``self.__x`` → ``self._Cls__x`` at runtime — out of scope for v0.1).
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule._python_dynamism import (
    has_dataclass_decorator,
    has_framework_base,
)
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class UnusedPrivateAttributeRule(Rule):
    ID = "dead-code.unused-private-attribute"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Unused private attribute",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for cls in ast.walk(unit.tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            if has_framework_base(cls) or has_dataclass_decorator(cls):
                continue

            assigned, read = _scan_class_self_attrs(cls)
            property_names = _collect_property_names(cls)
            for name, (_target, attr) in assigned.items():
                if not name.startswith("_"):
                    continue
                if name in read:
                    continue
                # @property backing fields: `self._x` paired with @property `x`
                # (or `_x` -> `x` convention)
                bare = name.lstrip("_")
                if bare in property_names:
                    continue

                parents = parent_chain(cls)
                class_symbol = qualified_symbol(cls, parents)
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(f"Class {class_symbol!r} assigns {name!r} but never reads it."),
                        file_path=unit.file.display_path,
                        line=attr.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=attr.end_lineno,
                        symbol=f"{class_symbol}.{name}",
                        remediation=(
                            "Remove the assignment or read the attribute somewhere "
                            "in the class body."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"attribute": name},
                    ),
                )
        return findings


def _scan_class_self_attrs(
    cls: ast.ClassDef,
) -> tuple[dict[str, tuple[ast.AST, ast.Attribute]], set[str]]:
    """Return (assigned, read) sets across all methods in *cls*.

    ``assigned`` maps name -> (containing-stmt-node, attribute-node) for the
    first assignment found. ``read`` is the set of names appearing as
    ``self.<name>`` in Load context."""
    assigned: dict[str, tuple[ast.AST, ast.Attribute]] = {}
    read: set[str] = set()
    for node in ast.walk(cls):
        if isinstance(node, ast.Attribute):
            if not (isinstance(node.value, ast.Name) and node.value.id == "self"):
                continue
            if isinstance(node.ctx, ast.Store):
                assigned.setdefault(node.attr, (node, node))
            elif isinstance(node.ctx, ast.Load | ast.Del):
                read.add(node.attr)
    return assigned, read


def _collect_property_names(cls: ast.ClassDef) -> set[str]:
    """Names of methods decorated with @property (or .setter / .getter)."""
    names: set[str] = set()
    for stmt in cls.body:
        if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for d in stmt.decorator_list:
            d_str = _decorator_repr(d)
            if d_str == "property" or d_str.endswith(".setter") or d_str.endswith(".getter"):
                names.add(stmt.name)
    return names


def _decorator_repr(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _decorator_repr(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_repr(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""
