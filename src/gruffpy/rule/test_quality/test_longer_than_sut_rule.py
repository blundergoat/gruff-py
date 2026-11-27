"""``test-quality.test-longer-than-sut`` - test function longer than the SUT it exercises.

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
from gruffpy.rule.size._lines import code_line_numbers, lines_for_size, parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class TestLongerThanSutRule(Rule):
    """Flag tests whose line count exceeds the matched SUT's by the configured ratio."""

    ID = "test-quality.test-longer-than-sut"

    def definition(self) -> RuleDefinition:
        """Describe the test-longer-than-sut rule with a configurable ratio option.

        Matching uses simple names within the same AST, including methods and nested functions; cross-module targets are unavailable.

        Returns:
            Definition with the ratio option controlling the test-to-SUT line-count threshold.
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
        """Flag tests whose line count exceeds ratio times the matching SUT function's lines.

        Match each test suffix to a function name in the same file. Skip cases with no match or a target of five code lines or fewer.
        Short targets are exempt because reasonable test setup can be much longer than the function itself.

        Args:
            unit: Source file containing the tests and candidate targets. The scan can cache code-line numbers on its AST.
            context: Rule execution context supplying the ratio option
                (test-to-SUT line ratio threshold).

        Returns:
            One finding per test that exceeds the ratio against its inferred target. Empty when no AST is available or no test qualifies.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        ratio = float(settings.options.get("ratio", definition.default_options["ratio"]))
        code_lines = code_line_numbers(unit.source, unit.tree)
        target_lengths = _function_lengths(unit.tree, code_lines)
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            target_name = _target_from_test_name(fn.name)
            if target_name is None:
                continue
            sut_len = target_lengths.get(target_name)
            if sut_len is None or sut_len <= 5:
                continue  # The ratio needs a matched target whose length makes the test comparison meaningful.
            test_len = lines_for_size(fn, code_lines)
            if test_len <= sut_len * ratio:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Test {symbol!r} is {test_len} lines for a {sut_len}-line SUT {target_name!r} (ratio {test_len / sut_len:.1f}x)."),
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
    """Extract the suffix used to match a test to a same-file function.

    Args:
        test_name: Test function name checked for a nonempty test_ suffix.

    Returns:
        The nonempty suffix after test_, or None when the prefix is absent or has no suffix.
    """
    if not test_name.startswith("test_"):
        return None
    candidate = test_name[len("test_") :]
    return candidate or None


def _function_lengths(tree: ast.AST, code_lines: frozenset[int]) -> dict[str, int]:
    """Index function code-line counts by their simple names.

    Args:
        tree: AST containing the synchronous and asynchronous function declarations to measure.
        code_lines: Line-number set supplied to the shared size measurement.

    Returns:
        Simple-name to line-count map; later visited functions replace entries with the same name.
    """
    out: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            out[node.name] = lines_for_size(node, code_lines)
    return out
