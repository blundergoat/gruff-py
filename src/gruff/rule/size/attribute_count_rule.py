"""``size.attribute-count`` — too many attributes signal an unfocused class."""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class AttributeCountRule(Rule):
    ID = "size.attribute-count"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Attribute count",
            pillar=Pillar.SIZE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 15, "error": 25},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue

            attrs = _collect_attributes(node)
            count = len(attrs)
            if count <= warning_threshold:
                continue

            if count > error_threshold:
                severity = Severity.ERROR
                threshold: int | float = error_threshold
            else:
                severity = Severity.WARNING
                threshold = warning_threshold

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Class {symbol!r} declares {count} attributes, "
                        f"above the {severity.value} threshold of {_format_number(threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=severity,
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
                        "threshold": threshold,
                        "thresholdDirection": "above",
                        "thresholdType": severity.value,
                    },
                ),
            )

        return findings


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
