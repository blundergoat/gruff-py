"""``test-quality.test-longer-than-sut`` — test function longer than the SUT it exercises.

Best-effort: identify the *target* function from the test's name
(``test_my_function`` → ``my_function``) and compare line counts. If the test is
more than 2× the SUT's length, fire.

Uses the ``lines_for_size`` helper per ADR-002 so the metric matches the
size pillar's policy.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import lines_for_size, parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class TestLongerThanSutRule(Rule):
    """Flag tests whose line count exceeds the matched SUT's by the configured ratio."""

    ID = "test-quality.test-longer-than-sut"

    def definition(self) -> RuleDefinition:
        """Describe the test-longer-than-sut rule with a configurable ``ratio`` option.

        Medium confidence because the SUT lookup is best-effort: only tests
        named ``test_<sut>`` get matched against an in-unit function named
        ``<sut>`` — cross-module SUTs and method tests don't pair up.

        Returns:
            Definition with the ``ratio`` option (test-to-SUT line ratio
            threshold).
        """
        return RuleDefinition(
            id=self.ID,
            name="Test longer than SUT",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"ratio": 2.0},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag tests whose line count exceeds ``ratio`` times the matching SUT function's lines.

        Skips tests where the SUT can't be located, where the SUT is
        trivial (≤5 lines, since a 50-line test for a 5-line SUT is
        plausible), or where the test name doesn't follow the
        ``test_<name>`` shape.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplying the ``ratio`` option
                (test-to-SUT line ratio threshold).

        Returns:
            One finding per test that exceeds the configured ratio against
            its inferred SUT.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        ratio = float(settings.options.get("ratio", definition.default_options["ratio"]))
        target_lengths = _function_lengths(unit.tree)
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            target_name = _target_from_test_name(fn.name)
            if target_name is None:
                continue
            sut_len = target_lengths.get(target_name)
            if sut_len is None or sut_len <= 5:
                continue  # trivial SUT or no match; skip
            test_len = lines_for_size(fn)
            if test_len <= sut_len * ratio:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} is {test_len} lines for a {sut_len}-line SUT "
                        f"{target_name!r} (ratio {test_len / sut_len:.1f}x)."
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
                        "Split the test into focused cases, or extract setup into a fixture. "
                        "Long tests for short SUTs often duplicate scenario boilerplate."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={
                        "testLines": test_len,
                        "sutLines": sut_len,
                        "target": target_name,
                    },
                ),
            )
        return findings


def _target_from_test_name(test_name: str) -> str | None:
    if not test_name.startswith("test_"):
        return None
    candidate = test_name[len("test_") :]
    return candidate or None


def _function_lengths(tree: ast.AST) -> dict[str, int]:
    out: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            out[node.name] = lines_for_size(node)
    return out
