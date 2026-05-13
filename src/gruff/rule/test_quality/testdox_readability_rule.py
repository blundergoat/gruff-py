"""``test-quality.testdox-readability`` (opt-in) — test name reads as a sentence.

Heuristic: test name has fewer than ``min_words`` lowercase-word tokens after
stripping the ``test_`` prefix. Default-off; an enforcement preference, not a
correctness check.
"""

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
from gruff.rule.test_quality._test_quality_node_helper import test_functions


class TestdoxReadabilityRule(Rule):
    ID = "test-quality.testdox-readability"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Testdox readability",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
            default_enabled=False,
            default_options={"min_words": 4},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        min_words = int(settings.options.get("min_words", definition.default_options["min_words"]))
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            stripped = fn.name.removeprefix("test_")
            words = [w for w in stripped.split("_") if w]
            if len(words) >= min_words:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} name has only {len(words)} word(s) — aim for "
                        f"at least {min_words} for a sentence-like description."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Rename the test to describe the behaviour, e.g. "
                        "`test_<subject>_<action>_<expected>`."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"wordCount": len(words), "minWords": min_words},
                ),
            )
        return findings
