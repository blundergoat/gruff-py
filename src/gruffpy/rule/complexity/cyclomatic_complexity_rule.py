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

The shared count above stays radon-aligned for its other consumers. The finding
rule discounts non-wildcard match cases after the first in each dispatch.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._walks import (
    FunctionLike,
    body_nodes,
    is_wildcard_pattern,
    iter_functions,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size import _band
from gruffpy.rule.size._band import LIMIT_BAND_KEY, band_advice, banded_severity, limit_band, limit_in_force
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.suppression.sensitive_exclusion_filter import is_built_in_test_path

_CYCLOMATIC_CACHE_ATTR = "_gruffpy_cyclomatic_complexity"


class CyclomaticComplexityRule(Rule):
    """Report functions over configured complexity thresholds, discounting extra match cases."""

    ID = "complexity.cyclomatic"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the cyclomatic complexity rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Cyclomatic complexity",
            pillar=Pillar.COMPLEXITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_threshold=20,
            # Off unless a project enables it: after its repair, 26 of 50 upper-band findings were worth acting on in the
            # 0.6.0 precision measurement, under the 0.60 floor; complexity.cognitive covers the same functions.
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze function-like nodes for cyclomatic complexity findings.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with threshold settings.

        Returns:
            Findings for functions above the configured complexity threshold.
        """
        if unit.tree is None:
            return []

        # A test's branches are its assertion sequence, which M14's upper-band labels found not worth splitting.
        if is_built_in_test_path(unit.file.display_path):
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            cc = cyclomatic_for(fn) - _extra_match_cases(fn)
            threshold_match = settings.high_value_threshold_match(cc)
            band = limit_band(cc, limit_in_force(settings))
            if threshold_match is None:
                continue

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has cyclomatic complexity {cc}, "
                        f"above the {threshold_match.severity.value} threshold of "
                        f"{_format_number(threshold_match.threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=banded_severity(band, threshold_match.severity),
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=band_advice(band, _band.LOWER_FUNCTION, _band.SIMPLIFY_PATH),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "complexity": cc,
                        "measuredValue": cc,
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "above",
                        "thresholdType": threshold_match.severity.value,
                        LIMIT_BAND_KEY: band,
                    },
                ),
            )
        return findings


def cyclomatic_for(fn: FunctionLike) -> int:
    """Return the McCabe cyclomatic complexity of a function-like node.

    Radon-aligned: base 1, plus decision points enumerated in the module
    docstring. Nested function bodies are skipped.

    Args:
        fn: Function, async function, or lambda node to score.

    Returns:
        Cyclomatic complexity score for the node body.
    """
    cached = getattr(fn, _CYCLOMATIC_CACHE_ATTR, None)
    if isinstance(cached, int):
        return cached

    count = 1
    for node in body_nodes(fn):
        count += _increment_for(node)
    setattr(fn, _CYCLOMATIC_CACHE_ATTR, count)
    return count


def _extra_match_cases(fn: FunctionLike) -> int:
    """Count the match cases after each match's first, which this rule takes back so a match is one decision.

    ``cyclomatic_for`` stays radon-aligned for the maintainability index and the docs rationale rule; only this rule
    reports a flat dispatch over many cases as the single decision a reader makes.

    Args:
        fn: Function, async function, or lambda node whose matches are counted.

    Returns:
        The number of non-wildcard cases beyond one, summed over every match in the function.
    """
    extra = 0
    for node in body_nodes(fn):
        if isinstance(node, ast.Match):
            cases = sum(1 for case in node.cases if not is_wildcard_pattern(case.pattern))
            extra += max(cases - 1, 0)
    return extra


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
