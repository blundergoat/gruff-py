"""Detect string formatting that can usually be expressed as an f-string."""

import ast
from typing import TypeGuard

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule


class FStringCandidateRule(Rule):
    """Report simple ``str.format(...)`` calls that can use f-strings."""

    ID = "modernisation.f-string-candidate"

    def definition(self) -> RuleDefinition:
        """Return metadata for the f-string modernisation rule.

        Returns:
            Definition under the modernisation pillar at advisory severity.
        """
        return RuleDefinition(
            id=self.ID,
            name="F-string candidate",
            pillar=Pillar.MODERNISATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag literal ``.format`` calls with arguments.

        Args:
            unit: Parsed Python source to inspect.
            context: Rule context; currently unused.

        Returns:
            One finding for each simple string literal format call.
        """
        del context
        if unit.tree is None:
            return []

        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not _is_literal_format_call(node):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message="String literal format call can usually be written as an f-string.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation="Use an f-string when the target Python version supports it.",
                    secondary_pillars=definition.secondary_pillars,
                    metadata={},
                )
            )
        return findings


def _is_literal_format_call(node: ast.AST) -> TypeGuard[ast.Call]:
    if not isinstance(node, ast.Call):
        return False
    if not isinstance(node.func, ast.Attribute):
        return False
    if node.func.attr != "format":
        return False
    if not node.args and not node.keywords:
        return False
    return isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
