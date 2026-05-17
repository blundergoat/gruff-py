"""``security.sql-concatenation`` — dynamic SQL passed to an execute()-style call.

Fires when a call whose target ends in ``execute`` / ``executemany`` /
``executescript`` / ``text`` receives a dynamic string as the first argument
(f-string, ``.format()``, ``%`` formatting, or ``+`` concatenation). Static
string literals and parameterised calls are safe.
"""

import ast
import re

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_metadata import finding_security_metadata
from gruffpy.rule.security._security_node_helper import (
    call_target_name,
    is_dynamic_string,
)

_SQL_EXECUTE_LEAVES: frozenset[str] = frozenset({"execute", "executemany", "executescript", "text"})
_QUOTED_PLACEHOLDER_RE = re.compile(
    r"""(?P<quote>['"])\s*(?:%s|%\([A-Za-z_][A-Za-z0-9_]*\)s|\?|:\w+|\$\d+)\s*(?P=quote)"""
)


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
            _sql_concatenation_finding(unit, definition, node, target, source_label)
            for node, target, source_label in _unsafe_sql_calls(unit.tree)
        ]


def _unsafe_sql_calls(tree: ast.AST) -> list[tuple[ast.Call, str, str]]:
    findings: list[tuple[ast.Call, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        candidate = _unsafe_sql_call(node)
        if candidate is not None:
            findings.append((node, *candidate))
    return findings


def _unsafe_sql_call(node: ast.Call) -> tuple[str, str] | None:
    target = call_target_name(node)
    if target is None or target.split(".")[-1] not in _SQL_EXECUTE_LEAVES:
        return None
    if not node.args:
        return None
    if is_dynamic_string(node.args[0]):
        return target, "dynamic-sql"
    if _uses_quoted_placeholder_with_parameters(node):
        return target, "quoted-placeholder"
    return None


def _uses_quoted_placeholder_with_parameters(call: ast.Call) -> bool:
    first_arg = call.args[0]
    if not isinstance(first_arg, ast.Constant) or not isinstance(first_arg.value, str):
        return False
    if not _has_parameter_argument(call):
        return False
    return bool(_QUOTED_PLACEHOLDER_RE.search(first_arg.value))


def _has_parameter_argument(call: ast.Call) -> bool:
    if len(call.args) > 1:
        return True
    return any(keyword.arg in {"parameters", "params"} for keyword in call.keywords)


def _sql_concatenation_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.Call,
    target: str,
    source_label: str,
) -> Finding:
    if source_label == "quoted-placeholder":
        message = (
            f"`{target}()` manually quotes a SQL placeholder while passing parameters — "
            "leave placeholders unquoted."
        )
    else:
        message = f"`{target}()` receives a dynamic SQL string — use parameterised arguments."
    return Finding(
        rule_id=definition.id,
        message=message,
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
        metadata={
            "target": target,
            **finding_security_metadata(
                definition.id,
                source_label=source_label,
                sink_label="sql-execution",
            ),
        },
    )
