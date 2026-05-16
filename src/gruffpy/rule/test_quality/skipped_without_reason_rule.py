"""``test-quality.skipped-without-reason`` — ``@pytest.mark.skip`` without a reason kwarg.

Skips without context become permanent. The rule requires a non-empty ``reason``
keyword argument (or first positional string for ``unittest.skip``).
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
from gruffpy.rule.security._security_node_helper import call_keyword, call_target_name
from gruffpy.rule.size._lines import parent_chain, qualified_symbol
from gruffpy.rule.test_quality._test_quality_node_helper import test_functions


class SkippedWithoutReasonRule(Rule):
    ID = "test-quality.skipped-without-reason"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Skipped without reason",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            decorator = _skip_decorator_without_reason(fn)
            if decorator is None:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"Test {symbol!r} is skipped without a `reason`.",
                    file_path=unit.file.display_path,
                    line=decorator.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=decorator.end_lineno,
                    symbol=symbol,
                    remediation=(
                        'Add a `reason="..."` argument explaining why the test is skipped '
                        "and what would unblock unskipping it."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _skip_decorator_without_reason(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.expr | None:
    for decorator in fn.decorator_list:
        if isinstance(decorator, ast.Call):
            target = call_target_name(decorator)
            if target is None:
                continue
            leaf = target.split(".")[-1]
            if leaf not in {"skip", "skipif", "skipIf", "skipUnless"}:
                continue
            reason = call_keyword(decorator, "reason") or _string_first_arg(decorator)
            if reason is None:
                return decorator
            if isinstance(reason, ast.Constant) and isinstance(reason.value, str):
                if not reason.value.strip():
                    return decorator
                continue
            continue  # Non-literal reason — assume the user wrote something.
        # Bare ``@pytest.mark.skip`` without parentheses → no reason ever supplied.
        target = _decorator_name(decorator)
        if target is None:
            continue
        leaf = target.split(".")[-1]
        if leaf == "skip":
            return decorator
    return None


def _string_first_arg(call: ast.Call) -> ast.expr | None:
    # For `skipif`, the first positional is the condition; reason is keyword.
    target = call_target_name(call)
    if target is None:
        return None
    leaf = target.split(".")[-1]
    if leaf == "skip" and call.args:
        return call.args[0]
    return None


def _decorator_name(decorator: ast.AST) -> str | None:
    if isinstance(decorator, ast.Name):
        return decorator.id
    if isinstance(decorator, ast.Attribute):
        prefix = _decorator_name(decorator.value)
        return f"{prefix}.{decorator.attr}" if prefix else decorator.attr
    return None
