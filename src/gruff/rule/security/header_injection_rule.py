"""``security.header-injection`` — ``response.headers[<dynamic>] = ...``.

Heuristic: subscript-assignment to an attribute named ``headers`` where the
subscript key is not a string literal. Scoped to files that import a known
web framework (Flask / FastAPI / Django / Starlette) to keep false-positive
risk low.
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
    frameworks_in_use,
    is_string_literal,
)

_FRAMEWORK_GATE: frozenset[str] = frozenset({"flask", "fastapi", "django"})


class HeaderInjectionRule(Rule):
    ID = "security.header-injection"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Header injection",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        if not (frameworks_in_use(unit.tree) & _FRAMEWORK_GATE):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Subscript):
                    continue
                value = target.value
                if not (isinstance(value, ast.Attribute) and value.attr == "headers"):
                    continue
                if is_string_literal(target.slice):
                    continue
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message="Response header key is dynamic — header injection risk.",
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        remediation=(
                            "Use literal header names. If a runtime-chosen name is "
                            "essential, validate against an explicit allowlist."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={},
                    ),
                )
        return findings
