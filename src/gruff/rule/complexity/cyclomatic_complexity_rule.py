"""McCabe cyclomatic complexity, radon-aligned.

Decision points (each +1):

- ``ast.If``, ``ast.For``, ``ast.AsyncFor``, ``ast.While``
- ``ast.ExceptHandler`` (per handler)
- ``ast.IfExp`` (ternary)
- ``ast.Assert``
- ``ast.match_case`` whose pattern is NOT the bare wildcard ``_``
- ``ast.BoolOp``: ``len(values) - 1`` per node (radon counts each operator)
- comprehension generators: 1 per ``ast.comprehension`` and 1 per ``if`` clause

Base value: 1 per function. Nested function definitions are scored
independently and do NOT contribute to the parent's count.
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.complexity._walks import (
    FunctionLike,
    body_nodes,
    is_wildcard_pattern,
    iter_functions,
)
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol


class CyclomaticComplexityRule(Rule):
    ID = "complexity.cyclomatic"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Cyclomatic complexity",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_thresholds={"warning": 10, "error": 20},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)
        warning_threshold = settings.numeric_threshold("warning")
        error_threshold = settings.numeric_threshold("error")

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            cc = cyclomatic_for(fn)
            if cc <= warning_threshold:
                continue
            if cc > error_threshold:
                severity = Severity.ERROR
                threshold: int | float = error_threshold
            else:
                severity = Severity.WARNING
                threshold = warning_threshold

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has cyclomatic complexity {cc}, "
                        f"above the {severity.value} threshold of {_format_number(threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Extract decision branches into helper functions; "
                        "replace nested conditionals with early returns or dispatch tables."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "complexity": cc,
                        "measuredValue": cc,
                        "threshold": threshold,
                        "thresholdDirection": "above",
                        "thresholdType": severity.value,
                    },
                ),
            )
        return findings


def cyclomatic_for(fn: FunctionLike) -> int:
    """Return the McCabe cyclomatic complexity of *fn*.

    Radon-aligned: base 1, plus decision points enumerated in the module
    docstring. Nested function bodies are skipped.
    """
    count = 1
    for node in body_nodes(fn):
        count += _increment_for(node)
    return count


def _increment_for(node: ast.AST) -> int:
    if isinstance(
        node,
        ast.If | ast.For | ast.AsyncFor | ast.While | ast.ExceptHandler | ast.IfExp | ast.Assert,
    ):
        return 1
    if isinstance(node, ast.match_case):
        return 0 if is_wildcard_pattern(node.pattern) else 1
    if isinstance(node, ast.BoolOp):
        return max(len(node.values) - 1, 0)
    if isinstance(node, ast.comprehension):
        return 1 + len(node.ifs)
    return 0


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
