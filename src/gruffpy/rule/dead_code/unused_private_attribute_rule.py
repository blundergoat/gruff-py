"""``self._x`` assigned in a class but never read anywhere in the class body.

Skip:

- dataclass field declarations (``@dataclass`` class with annotated fields);
- ``@property`` backing fields (``self._x`` paired with ``@property`` getter
  named ``x``);
- classes extending ABC/Protocol (framework hooks);
- name-mangled attributes that the body accesses with the mangled form
  (``self.__x`` → ``self._Cls__x`` at runtime - out of scope for v0.1).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    has_dataclass_decorator,
    has_framework_base,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class UnusedPrivateAttributeRule(Rule):
    """Detect `self._x` attributes assigned in a class but never read within it."""

    ID = "dead-code.unused-private-attribute"

    def definition(self) -> RuleDefinition:
        """Describe the unused-private-attribute rule as a medium-confidence warning.

        Medium confidence: ``__x``-style name-mangled attributes accessed via
        the runtime-mangled name (``self._Cls__x``) are out of scope and can
        false-positive.

        Returns:
            Definition for the unused-private-attribute rule under the
            dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unused private attribute",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``self._x``-style assignments inside a class that the class never reads.

        Skips dataclasses (fields are intentionally write-only at the type
        level), framework-base subclasses, and ``_x`` attributes paired with
        an ``@property x`` getter (the underscore is the backing field).
        Honours the dead-code allowlist by path, symbol, and decorator.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the allowlist.

        Returns:
            One finding per private attribute assigned-but-never-read.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        allowlist = context.config.dead_code_allowlist
        if allowlist.matches_path(unit.file.display_path):
            return []
        findings: list[Finding] = []
        for cls in _candidate_classes(unit.tree):
            if allowlist.matches_decorator(_decorator_names(cls.decorator_list)):
                continue
            for finding in _unused_attribute_findings(unit, definition, cls):
                if allowlist.matches_symbol(finding.symbol):
                    continue
                findings.append(finding)
        return findings


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


def _candidate_classes(tree: ast.AST) -> list[ast.ClassDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and not has_framework_base(node)
        and not has_dataclass_decorator(node)
    ]


def _unused_attribute_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    cls: ast.ClassDef,
) -> list[Finding]:
    assigned, read = _scan_class_self_attrs(cls)
    property_names = _collect_property_names(cls)
    parents = parent_chain(cls)
    class_symbol = qualified_symbol(cls, parents)
    return [
        _unused_attribute_finding(unit, definition, class_symbol, name, attr)
        for name, (_target, attr) in assigned.items()
        if _is_unused_private_attribute(name, read, property_names)
    ]


def _is_unused_private_attribute(
    name: str,
    read: set[str],
    property_names: set[str],
) -> bool:
    if not name.startswith("_"):
        return False
    if name in read:
        return False
    return name.lstrip("_") not in property_names


def _unused_attribute_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    class_symbol: str,
    name: str,
    attribute: ast.Attribute,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(f"Class {class_symbol!r} assigns {name!r} but never reads it."),
        file_path=unit.file.display_path,
        line=attribute.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=attribute.end_lineno,
        symbol=f"{class_symbol}.{name}",
        remediation=("Remove the assignment or read the attribute somewhere in the class body."),
        secondary_pillars=definition.secondary_pillars,
        metadata={"attribute": name},
    )


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
        for decorator in stmt.decorator_list:
            decorator_name = _decorator_repr(decorator)
            if (
                decorator_name == "property"
                or decorator_name.endswith(".setter")
                or decorator_name.endswith(".getter")
            ):
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
