"""``security.variable-import`` — dynamic module name passed to importlib / ``__import__``.

Fires on ``importlib.import_module(<non-literal>)`` and ``__import__(<non-literal>)``.
``exec("import " + name)`` is caught by ``security.dangerous-function-call`` so
this rule deliberately does not duplicate that shape.
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
    call_target_name,
    is_string_literal,
)

_VARIABLE_IMPORT_TARGETS: frozenset[str] = frozenset(
    {"importlib.import_module", "__import__", "import_module"}
)


class VariableImportRule(Rule):
    ID = "security.variable-import"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Variable import",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
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
            if target not in _VARIABLE_IMPORT_TARGETS:
                continue
            if not node.args:
                continue
            first = node.args[0]
            if is_string_literal(first):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"`{target}(...)` with a non-literal module name.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Validate the module name against an explicit allowlist before "
                        "passing it to ``importlib.import_module``."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target},
                ),
            )
        return findings
