"""``test-quality.setup-bloat`` — ``setUp`` / ``setup_method`` / fixture is too long.

A setup that's longer than the typical test signals over-shared state. Default
threshold: 30 lines. Uses the M02 ``lines_for_size`` helper.
"""

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
from gruff.rule.security._security_node_helper import call_target_name
from gruff.rule.size._lines import lines_for_size, parent_chain, qualified_symbol

_SETUP_NAMES: frozenset[str] = frozenset(
    {"setUp", "setUpClass", "setup_method", "setup_class", "setup_function", "setup"}
)


class SetupBloatRule(Rule):
    ID = "test-quality.setup-bloat"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Setup bloat",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_thresholds={"warning": 30},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        threshold = settings.numeric_threshold("warning")
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not _is_setup(node):
                continue
            lines = lines_for_size(node)
            if lines <= threshold:
                continue
            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Setup {symbol!r} is {lines} lines, above the threshold of {threshold}."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Shrink the shared setup — extract object factories, narrow what "
                        "each test actually needs."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"lines": lines, "threshold": threshold},
                ),
            )
        return findings


def _is_setup(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if fn.name in _SETUP_NAMES:
        return True
    return any(
        (call_target_name(d) or "").split(".")[-1] == "fixture"
        for d in fn.decorator_list
        if isinstance(d, ast.Call)
    )
