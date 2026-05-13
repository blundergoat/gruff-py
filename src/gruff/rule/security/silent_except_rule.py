"""``security.silent-except`` — ``except:`` or ``except Exception:`` body is pass-only.

Suppressed when the handler body contains any logging call (``logger.error``,
``logging.exception``, ``print``, etc.) — that's not silent, even if the
exception is then swallowed.
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
from gruff.rule.security._security_node_helper import (
    body_is_pass_or_ellipsis,
    exception_handler_logs,
)

_WIDE_EXCEPTION_LEAVES: frozenset[str] = frozenset({"Exception", "BaseException"})


class SilentExceptRule(Rule):
    ID = "security.silent-except"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Silent except",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not _is_wide_exception(node):
                continue
            if not body_is_pass_or_ellipsis(node.body):
                continue
            if exception_handler_logs(node):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="Exception silently swallowed (pass-only handler).",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Log the exception, re-raise, or catch a specific exception type "
                        "and handle it deliberately."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                ),
            )
        return findings


def _is_wide_exception(handler: ast.ExceptHandler) -> bool:
    """True if the handler catches no specific type, or catches Exception/BaseException."""
    if handler.type is None:
        return True
    if isinstance(handler.type, ast.Name):
        return handler.type.id in _WIDE_EXCEPTION_LEAVES
    if isinstance(handler.type, ast.Attribute):
        return handler.type.attr in _WIDE_EXCEPTION_LEAVES
    return False
