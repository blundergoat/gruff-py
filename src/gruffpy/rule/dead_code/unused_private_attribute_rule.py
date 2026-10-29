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
    """List each decorator's dotted name, plus its last segment when dotted, for the allowlist decorator match.

    Args:
        decorators: Decorator expressions of a candidate class, in source order.

    Returns:
        Names in decorator order, each dotted name followed by its last segment when the two differ; a decorator that _decorator_repr renders as an
        empty string is omitted, so the tuple may be empty.
    """
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
    """List every class in the tree, nested ones too, unless has_framework_base or has_dataclass_decorator is true.

    Args:
        tree: Parsed module tree to walk for class definitions.

    Returns:
        Class nodes in ast.walk order; empty when the tree has no class or every class is excluded.
    """
    return [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and not has_framework_base(node) and not has_dataclass_decorator(node)]


def _unused_attribute_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    cls: ast.ClassDef,
) -> list[Finding]:
    """Build a finding for each underscore-prefixed self attribute the class assigns but never reads or deletes.

    Assignments and reads come from _scan_class_self_attrs and property names from _collect_property_names; _is_unused_private_attribute makes the
    per-name decision, which also skips property backing fields. The dead-code allowlist symbol match is left to the caller.

    Args:
        unit: Analysis unit whose display path the findings report.
        definition: Rule definition supplying the rule id, default severity, pillar, tier, confidence and secondary pillars copied into each finding.
        cls: Candidate class whose subtree is scanned and whose qualified symbol prefixes each finding symbol.

    Returns:
        One finding per qualifying attribute name, in the order the class walk first meets each assignment; empty when no name qualifies.
    """
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
    """Decide whether a self attribute name is underscore-prefixed, not in read, and not a property backing field.

    A name counts as a backing field when stripping all its leading underscores yields one of the property names, so ``_x`` and ``__x`` both pair with
    a property method named ``x``.

    Args:
        name: Attribute name assigned on self somewhere in the class.
        read: Attribute names the class reads or deletes on self.
        property_names: Names of the class's methods decorated as a property, setter or getter.

    Returns:
        True when the name should be reported; False when it lacks a leading underscore, appears in read, or matches a property name after its leading
        underscores are stripped.
    """
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
    """Build the finding for one underscore-prefixed self attribute that the class assigns but never reads.

    The finding symbol is the class symbol and the attribute name joined by a dot, and its metadata records the attribute name under the attribute
    key.

    Args:
        unit: Analysis unit whose display path the finding reports.
        definition: Rule definition supplying the rule id, default severity, pillar, tier, confidence and secondary pillars.
        class_symbol: Qualified symbol of the class, used in the message and as the finding symbol prefix.
        name: Attribute name as assigned on self, leading underscores included.
        attribute: Attribute node of the assignment, whose start and end lines locate the finding.

    Returns:
        Finding at the rule's default severity whose message names the class and attribute and whose remediation asks to remove the assignment or read
        the attribute in the class body.
    """
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
    """Collect the attribute names assigned to, and read or deleted from, a bare self name anywhere in the class.

    The walk covers the whole class subtree, nested functions and classes included, and ignores attributes on any receiver other than the bare name
    self. A Store context counts as an assignment, so an augmented assignment such as ``self._x += 1`` records only an assignment; Load and Del
    contexts count as reads. For each assigned name only the first assignment the breadth-first walk meets is kept.

    Returns:
        A pair of a dict mapping each assigned name to a tuple holding its first assignment's attribute node twice, and the set of names read or
        deleted on self.
    """
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
    """Names of methods decorated with @property (or .setter / .getter).

    Returns:
        Names of methods defined directly in the class body with a decorator rendered exactly as property or ending in .setter or .getter; empty when
        none match.
    """
    names: set[str] = set()
    for stmt in cls.body:
        if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for decorator in stmt.decorator_list:
            decorator_name = _decorator_repr(decorator)
            if decorator_name == "property" or decorator_name.endswith(".setter") or decorator_name.endswith(".getter"):
                names.add(stmt.name)
    return names


def _decorator_repr(decorator: ast.AST) -> str:
    """Render a decorator expression as its dotted name, reducing a call to the expression it calls.

    Args:
        decorator: Decorator expression, or the callee or attribute base reached while recursing.

    Returns:
        The dotted name built from names and attributes; an attribute whose base renders empty yields only the attribute name, and any other
        expression yields an empty string.
    """
    if isinstance(decorator, ast.Call):
        return _decorator_repr(decorator.func)
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_repr(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return ""
