"""``security.sql-concatenation`` — dynamic SQL passed to an execute()-style call.

Fires when a call whose target ends in ``execute`` / ``executemany`` /
``executescript`` / ``text`` receives a dynamic string as the first argument
(f-string, ``.format()``, ``%`` formatting, or ``+`` concatenation). Static
string literals and parameterised calls are safe.
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
    is_dynamic_string,
)

_SQL_EXECUTE_LEAVES: frozenset[str] = frozenset({"execute", "executemany", "executescript", "text"})


class SqlConcatenationRule(Rule):
    ID = "security.sql-concatenation"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="SQL concatenation",
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
            if target is None:
                continue
            leaf = target.split(".")[-1]
            if leaf not in _SQL_EXECUTE_LEAVES:
                continue
            if not node.args:
                continue
            first = node.args[0]
            if not is_dynamic_string(first):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"`{target}()` receives a dynamic SQL string — use parameterised arguments."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Pass values as a separate parameter sequence: "
                        "``cursor.execute('SELECT * FROM t WHERE id = ?', (id,))``."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target},
                ),
            )
        return findings
