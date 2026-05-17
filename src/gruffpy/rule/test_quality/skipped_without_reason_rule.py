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

_SKIP_DECORATOR_LEAVES: frozenset[str] = frozenset(
    {"skip", "skipif", "skipIf", "skipUnless"}
)


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
        if _is_skip_call_without_reason(decorator) or _is_bare_skip_decorator(decorator):
            return decorator
    return None


def _is_skip_call_without_reason(decorator: ast.expr) -> bool:
    if not isinstance(decorator, ast.Call):
        return False
    if _skip_call_leaf(decorator) is None:
        return False
    reason = call_keyword(decorator, "reason") or _string_first_arg(decorator)
    return _is_missing_reason(reason)


def _skip_call_leaf(call: ast.Call) -> str | None:
    target = call_target_name(call)
    if target is None:
        return None
    leaf = target.split(".")[-1]
    return leaf if leaf in _SKIP_DECORATOR_LEAVES else None


def _is_missing_reason(reason: ast.expr | None) -> bool:
    if reason is None:
        return True
    if isinstance(reason, ast.Constant) and isinstance(reason.value, str):
        return not reason.value.strip()
    return False


def _is_bare_skip_decorator(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Call):
        return False
    target = _decorator_name(decorator)
    if target is None:
        return False
    return target.split(".")[-1] == "skip"


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
