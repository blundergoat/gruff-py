"""``security.silent-except`` — ``except:`` or ``except Exception:`` body is pass-only.

Suppressed when the handler body contains any logging call (``logger.error``,
``logging.exception``, ``print``, etc.) — that's not silent, even if the
exception is then swallowed.
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
from gruffpy.rule.security._security_node_helper import (
    does_exception_handler_log,
    is_pass_or_ellipsis_body,
)

_WIDE_EXCEPTION_LEAVES: frozenset[str] = frozenset({"Exception", "BaseException"})


class SilentExceptRule(Rule):
    """Detect wide `except` handlers whose body only passes and never logs the exception."""

    ID = "security.silent-except"

    def definition(self) -> RuleDefinition:
        """Describe the silent-except rule as a high-confidence advisory.

        Advisory rather than warning because silent swallowing can be
        intentional (fire-and-forget cleanup, optional best-effort steps).
        High confidence because the matched shape is narrow: wide ``except``
        target, pass-only body, and no logging call in the handler.

        Returns:
            Definition for the silent-except rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Silent except",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``except:`` / ``except Exception:`` whose body is just ``pass`` / ``...``.

        A logging call in the handler (``logger.error``,
        ``logging.exception``, ``print``, etc.) defuses the rule — the
        exception is observable even when swallowed.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per pass-only wide ``except`` handler that doesn't log.
        """
        if unit.tree is None or "except" not in unit.source:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if not _is_wide_exception(node):
                continue
            if not is_pass_or_ellipsis_body(node.body):
                continue
            if does_exception_handler_log(node):
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
