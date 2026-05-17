"""``security.sql-concatenation`` — dynamic SQL passed to an execute()-style call.

Fires when a call whose target ends in ``execute`` / ``executemany`` /
``executescript`` / ``text`` receives a dynamic string as the first argument
(f-string, ``.format()``, ``%`` formatting, or ``+`` concatenation). Static
string literals and parameterised calls are safe.
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
        return [
            _sql_concatenation_finding(unit, definition, node, target)
            for node, target in _dynamic_sql_calls(unit.tree)
        ]


def _dynamic_sql_calls(tree: ast.AST) -> list[tuple[ast.Call, str]]:
    findings: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = _dynamic_sql_target(node)
        if target is not None:
            findings.append((node, target))
    return findings


def _dynamic_sql_target(node: ast.Call) -> str | None:
    target = call_target_name(node)
    if target is None or target.split(".")[-1] not in _SQL_EXECUTE_LEAVES:
        return None
    if not node.args or not is_dynamic_string(node.args[0]):
        return None
    return target


def _sql_concatenation_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.Call,
    target: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(f"`{target}()` receives a dynamic SQL string — use parameterised arguments."),
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
    )
