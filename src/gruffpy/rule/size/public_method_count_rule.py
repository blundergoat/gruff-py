"""``size.public-method-count`` — too many public methods widen the maintenance surface."""

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


class PublicMethodCountRule(Rule):
    """Flag classes whose direct public method count exceeds the threshold (default 10)."""

    ID = "size.public-method-count"

    def definition(self) -> RuleDefinition:
        """Describe the public-method-count rule with a configurable threshold (default 10).

        Returns:
            Definition under the size pillar; methods starting with ``_``
            (including dunder methods) are excluded from the count.
        """
        return RuleDefinition(
            id=self.ID,
            name="Public method count",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 10, "error": 10},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Emit one finding per class whose public-method count exceeds the threshold.

        Only direct methods of the class body are counted — nested classes
        are reported separately. The metric is a proxy for the size of the
        class's external API.

        Args:
            unit: Parsed source file to walk.
            context: Rule execution context that supplies the threshold.

        Returns:
            One finding per ``ClassDef`` whose public-method count is over
            threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if _is_exempt_from_method_count(node):
                continue

            count = _count_public_methods(node)
            threshold_match = settings.high_value_threshold_match(count)
            if threshold_match is None:
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Class {symbol!r} has {count} public methods, "
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
                    remediation=("Split responsibilities; extract collaborator classes."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "publicMethods": count,
                        "measuredValue": count,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )

        return findings


def _is_exempt_from_method_count(cls: ast.ClassDef) -> bool:
    # Test classes have one method per test case by design; counting them
    # against an API-surface threshold yields no useful signal. Schema bases
    # (TypedDict, BaseModel, NamedTuple, Enum-like) also do not represent
    # behavioural surface area.
    return is_test_class(cls) or has_framework_base(cls) or has_dataclass_decorator(cls)


def _count_public_methods(cls: ast.ClassDef) -> int:
    count = 0
    for stmt in cls.body:
        if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        name = stmt.name
        if name.startswith("_"):
            # Includes single-underscore private and dunder methods.
            continue
        count += 1
    return count


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
