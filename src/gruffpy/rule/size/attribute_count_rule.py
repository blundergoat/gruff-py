"""``size.attribute-count`` - too many attributes signal an unfocused class."""

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
    is_test_class,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size import _band
from gruffpy.rule.size._band import LIMIT_BAND_KEY, band_advice, banded_severity, limit_band, limit_in_force
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class AttributeCountRule(Rule):
    """Flag classes whose deduped attribute count (class body + ``self.x`` in init) exceeds 15."""

    ID = "size.attribute-count"

    def definition(self) -> RuleDefinition:
        """Describe the attribute-count rule with a configurable attribute threshold (default 15).

        Returns:
            Definition under the size pillar; the threshold applies to the
            union of class-body attributes and ``self.x`` assignments
            discovered in ``__init__``.
        """
        return RuleDefinition(
            id=self.ID,
            name="Attribute count",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=15,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per class whose attribute count exceeds the threshold.

        Attribute names are deduplicated, so a class-level annotation that
        is re-assigned in ``__init__`` counts once. Tuple-target unpacking
        in ``__init__`` (``self.a, self.b = ...``) is supported.

        Args:
            unit: Parsed source file to walk.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per ``ClassDef`` whose deduped attribute count is
            over threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if _is_exempt_from_attribute_count(node):
                continue

            attrs = _collect_attributes(node)
            count = len(attrs)
            threshold_match = settings.high_value_threshold_match(count)
            band = limit_band(count, limit_in_force(settings))
            if threshold_match is None:
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Class {symbol!r} declares {count} attributes, "
                        f"above the {threshold_match.severity.value} threshold of "
                        f"{_format_number(threshold_match.threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=banded_severity(band, threshold_match.severity),
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=band_advice(band, _band.LOWER_ATTRIBUTE, _band.SPLIT_CLASS),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "attributes": count,
                        "measuredValue": count,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                        LIMIT_BAND_KEY: band,
                    },
                ),
            )

        return findings


def _is_exempt_from_attribute_count(cls: ast.ClassDef) -> bool:
    """Report whether the attribute-count rule skips this class as a test class, framework-base subclass or dataclass.

    Returns:
        True when the class is a unittest or pytest test class, extends a framework base such as Protocol, ABC, TypedDict, NamedTuple, an Enum type or
        pydantic BaseModel, or carries a dataclass or attrs-style decorator, so analyse skips it without counting its attributes; False when its
        attributes are counted.
    """
    # Schemas (TypedDict, BaseModel, NamedTuple, Enum-like) and dataclasses
    # enumerate their fields by design; counting them against an
    # "unfocused class" threshold misses the intent. Test classes likewise
    # carry per-case fixture attributes that aren't behavioural state.
    return is_test_class(cls) or has_framework_base(cls) or has_dataclass_decorator(cls)


def _collect_attributes(cls: ast.ClassDef) -> set[str]:
    """Return the deduped attribute-name set for *cls*.

    Combines class-body annotated/assigned names with the names assigned to
    ``self.<x>`` inside ``__init__``. Dedupe key is the bare attribute name.
    """
    names: set[str] = set()
    for stmt in cls.body:
        names.update(_class_body_names(stmt))
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef) and stmt.name == "__init__":
            names.update(_init_self_assignments(stmt))
    return names


def _class_body_names(stmt: ast.AST) -> set[str]:
    """Collect the attribute names that one class-body statement binds by assigning or annotating a bare name.

    Args:
        stmt: One statement from the class body. Only an annotated assignment to a single name, with or without a value, and a plain assignment are
            inspected; every other statement contributes nothing.

    Returns:
        The names the statement binds directly, including each name in a chained assignment; empty for other statement kinds and for tuple-unpacking,
        attribute or subscript targets.
    """
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        return {stmt.target.id}
    if isinstance(stmt, ast.Assign):
        out: set[str] = set()
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                out.add(target.id)
        return out
    return set()


def _init_self_assignments(init: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Collect the attribute names that an __init__ method assigns on self.

    The walk covers the whole method, including nested functions and classes, and matches the literal name self rather than the method's first
    parameter, so any plain or annotated assignment target spelled self.<name> counts.

    Args:
        init: The __init__ method node found directly in the class body, sync or async.

    Returns:
        Attribute names from plain and annotated assignments whose target is self.<name>, including names inside tuple or list unpacking targets but
        not starred elements; empty when the method assigns no such attribute.
    """
    names: set[str] = set()
    for sub in ast.walk(init):
        if isinstance(sub, ast.Assign):
            for target in sub.targets:
                _collect_self_attribute(target, names)
        elif isinstance(sub, ast.AnnAssign):
            _collect_self_attribute(sub.target, names)
    return names


def _collect_self_attribute(target: ast.AST, names: set[str]) -> None:
    """Add the name from a self.<name> assignment target to the set, descending into tuple and list unpacking.

    Args:
        target: One assignment target. A self.<name> attribute contributes its name, a tuple or list is searched element by element, and anything
            else, including a starred element or a deeper chain such as self.a.b, is ignored.
        names: The attribute-name set being built for the current __init__ method; it is mutated in place with each matched name.
    """
    if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
        names.add(target.attr)
    elif isinstance(target, ast.Tuple | ast.List):
        for elt in target.elts:
            _collect_self_attribute(elt, names)


def _format_number(value: int | float) -> str:
    """Render a threshold for the finding message without a trailing .0 on whole-number values.

    Args:
        value: The threshold to render, as an int or a float.

    Returns:
        The float's str form when it has a fractional part, otherwise the value as an integer string, so 15.0 renders as 15.
    """
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
