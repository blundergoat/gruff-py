"""Maintainability index per function.

Formula: ``MI = 171 - 5.2·ln(HV) - 0.23·CC - 16.2·ln(LOC)``, clamped to ``[0, 100]``.

Consumes Halstead volume (`_halstead.halstead_for`), cyclomatic complexity
(`cyclomatic_complexity_rule.cyclomatic_for`), and the M02 line-counting
helper (`gruff.rule.size._lines.lines_for_size`) — ADR-002 requires the
LOC term to share the helper, not be re-derived locally.

Lower MI = worse; the rule emits when MI < threshold (default warning=55,
error=35). Pillar: ``maintainability`` so this metric surfaces separately
from per-function complexity.
"""

import math

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.complexity._halstead import halstead_for
from gruff.rule.complexity._walks import FunctionLike, iter_functions
from gruff.rule.complexity.cyclomatic_complexity_rule import cyclomatic_for
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule
from gruff.rule.size._lines import lines_for_size, parent_chain, qualified_symbol


class MaintainabilityIndexRule(Rule):
    ID = "complexity.maintainability-index"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Maintainability index",
            pillar=Pillar.MAINTAINABILITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 55, "error": 35},
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
            mi = maintainability_index_for(fn)
            # Lower is worse: emit when MI < threshold.
            if mi >= warning_threshold:
                continue
            if mi < error_threshold:
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
                        f"Function {symbol!r} has maintainability index {mi:.1f}, "
                        f"below the {severity.value} threshold of {_format_number(threshold)}."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=("Reduce length, complexity, or operator vocabulary to raise MI."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "maintainabilityIndex": round(mi, 2),
                        "threshold": threshold,
                        "thresholdType": severity.value,
                    },
                ),
            )
        return findings


def maintainability_index_for(fn: FunctionLike) -> float:
    """Compute MI for *fn* using the canonical formula.

    Uses the M02 `lines_for_size()` helper for LOC so this rule does not
    re-derive line counts (ADR-002 cross-impl invariant).
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
