"""Maintainability index per function.

Formula: ``MI = 171 - 5.2·ln(HV) - 0.23·CC - 16.2·ln(LOC)``, clamped to ``[0, 100]``.

Consumes Halstead volume (`_halstead.halstead_for`), cyclomatic complexity
(`cyclomatic_complexity_rule.cyclomatic_for`), and the shared line-counting
helper (`gruff.rule.size._lines.lines_for_size`) - ADR-002 requires the
LOC term to share the helper, not be re-derived locally.

Lower MI = worse; the rule emits when MI is below the configured threshold.
Pillar: ``maintainability`` so this metric surfaces separately from
per-function complexity.
"""

import math

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity._halstead import halstead_for
from gruffpy.rule.complexity._walks import FunctionLike, iter_functions
from gruffpy.rule.complexity.cyclomatic_complexity_rule import cyclomatic_for
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import lines_for_size, parent_chain, qualified_symbol


class MaintainabilityIndexRule(Rule):
    """Report functions whose maintainability index is below configured thresholds."""

    ID = "complexity.maintainability-index"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the maintainability index rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Maintainability index",
            pillar=Pillar.MAINTAINABILITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 80, "error": 70},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze function-like nodes for maintainability index findings.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context with threshold settings.

        Returns:
            Findings for functions below the configured maintainability threshold.
        """
        if unit.tree is None:
            return []

        definition = self.definition()
        settings = context.settings_for(definition)

        findings: list[Finding] = []
        for fn in iter_functions(unit.tree):
            mi = maintainability_index_for(fn)
            threshold_match = settings.low_value_threshold_match(mi)
            if threshold_match is None:
                continue

            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has maintainability index {mi:.1f}, "
                        f"below the {threshold_match.severity.value} threshold of "
                        f"{_format_number(threshold_match.threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=threshold_match.severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=("Reduce length, complexity, or operator vocabulary to raise MI."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "maintainabilityIndex": round(mi, 2),
                        "measuredValue": round(mi, 2),
                        "threshold": threshold_match.threshold,
                        "thresholdDirection": "below",
                        "thresholdType": threshold_match.severity.value,
                    },
                ),
            )
        return findings


def maintainability_index_for(fn: FunctionLike) -> float:
    """Compute maintainability index for a function-like node.

    Uses the shared `lines_for_size()` helper for LOC so this rule does not
    re-derive line counts (ADR-002 cross-impl invariant).

    Args:
        fn: Function, async function, or lambda node to score.

    Returns:
        Maintainability index clamped to the range 0 through 100.
    """
    hv = halstead_for(fn).volume
    cc = cyclomatic_for(fn)
    loc = lines_for_size(fn) if fn.end_lineno is not None else 1
    # Guard against ln(0): treat zero terms as 1.
    log_hv = math.log(hv) if hv > 0 else 0.0
    log_loc = math.log(loc) if loc > 0 else 0.0
    raw = 171 - 5.2 * log_hv - 0.23 * cc - 16.2 * log_loc
    return max(0.0, min(100.0, raw))


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and not value.is_integer():
        return str(value)
    return str(int(value))
