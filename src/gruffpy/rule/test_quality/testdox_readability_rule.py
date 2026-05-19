"""``test-quality.testdox-readability`` (opt-in) — test name reads as a sentence.

Heuristic: test name has fewer than ``min_words`` lowercase-word tokens after
stripping the ``test_`` prefix. Default-off; an enforcement preference, not a
correctness check.
"""

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class TestdoxReadabilityRule(Rule):
    """Flag test names with fewer than `min_words` snake_case tokens after the `test_` prefix."""

    ID = "test-quality.testdox-readability"

    def definition(self) -> RuleDefinition:
        """Describe the testdox-readability rule as an opt-in low-confidence stylistic preference.

        Low confidence and default-off because word-count is a crude proxy
        for readability: ``test_login_succeeds_with_valid_credentials``
        reads well at 5 tokens, but ``test_x_y_z`` is only stylistically bad
        — not wrong.

        Returns:
            Definition with ``default_enabled=False`` and the ``min_words``
            option (default 4).
        """
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
        """Flag tests whose name (sans ``test_``) has fewer than ``min_words`` underscore tokens.

        Counts non-empty tokens from splitting on underscores; the
        sentence-like ``test_<subject>_<action>_<expected>`` shape
        comfortably clears the default threshold of 4.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``min_words``
                option.

        Returns:
            One finding per test whose stripped name has too few tokens.
        """
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
