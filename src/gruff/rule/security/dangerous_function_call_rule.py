"""``security.dangerous-function-call`` — eval / exec / compile / dynamic __import__.

Fires unconditionally on ``eval``, ``exec``, and ``compile``. ``__import__``
is only flagged when called with a non-literal first argument (literal
imports are equivalent to a normal import statement).
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
    call_target_name,
    is_string_literal,
)

_UNCONDITIONAL_DANGEROUS: frozenset[str] = frozenset({"eval", "exec", "compile"})


class DangerousFunctionCallRule(Rule):
    ID = "security.dangerous-function-call"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Dangerous function call",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = call_target_name(node)
            if target is None:
                continue

            kind: str | None = None
            if target in _UNCONDITIONAL_DANGEROUS:
                kind = target
            elif target == "__import__":
                first = node.args[0] if node.args else None
                if first is not None and not is_string_literal(first):
                    kind = "__import__"
            if kind is None:
                continue

            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(f"Dangerous call to `{kind}()` — arbitrary code execution surface."),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Replace with structured deserialisation or an explicit dispatch "
                        "table. If you genuinely need dynamic code, isolate it in a "
                        "sandboxed subprocess."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": kind},
                ),
            )
        return findings
