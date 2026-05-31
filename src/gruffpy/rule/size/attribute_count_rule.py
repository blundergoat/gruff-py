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
                    severity=threshold_match.severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=("Group related attributes into a sub-object or value object."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "attributes": count,
                        "measuredValue": count,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )

        return findings


def _is_exempt_from_attribute_count(cls: ast.ClassDef) -> bool:
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
    names: set[str] = set()
    for sub in ast.walk(init):
        if isinstance(sub, ast.Assign):
            for target in sub.targets:
                _collect_self_attr(target, names)
        elif isinstance(sub, ast.AnnAssign):
            _collect_self_attr(sub.target, names)
    return names


def _collect_self_attr(target: ast.AST, names: set[str]) -> None:
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id == "self"
    ):
        names.add(target.attr)
    elif isinstance(target, ast.Tuple | ast.List):
        for elt in target.elts:
            _collect_self_attr(elt, names)


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
