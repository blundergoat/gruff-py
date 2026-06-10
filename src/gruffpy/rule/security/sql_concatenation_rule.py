"""``security.sql-concatenation`` - dynamic SQL passed to an execute()-style call.

Fires when a SQL execution sink receives a dynamic SQL string as the first
argument (f-string, ``.format()``, ``%`` formatting, or ``+`` concatenation).
Static string literals, non-SQL command strings, and strings built only from
same-module ALL-CAPS constants are safe.
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
    fixed_string_fragments,
    frameworks_in_use,
    is_dynamic_string,
    is_fixed_string_expression,
    module_string_constants,
)

_SQL_EXECUTE_LEAVES: frozenset[str] = frozenset({"execute", "executemany", "executescript", "text"})
_SOURCE_NEEDLES: tuple[str, ...] = ("execute", "executemany", "executescript", "text")
_SQL_KEYWORD_RE = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|ALTER|DROP|CREATE|REPLACE|TRUNCATE|FROM|WHERE)\b",
    re.IGNORECASE,
)
_VALUE_INTERPOLATION_CONTEXT_RE = re.compile(
    r"(?:=|<>|!=|<=|>=|<|>|\bLIKE\b|\bILIKE\b)\s*['\"]?\s*$",
    re.IGNORECASE,
)
_STRUCTURE_INTERPOLATION_CONTEXT_RE = re.compile(
    r"(?:\bFROM\b|\bJOIN\b|\bUPDATE\b|\bINTO\b|\bTABLE\b|\bSELECT\b|\bORDER\s+BY\b|"
    r"\bGROUP\s+BY\b|\bIN)\s*\(?\s*$",
    re.IGNORECASE,
)
_QUOTED_PLACEHOLDER_RE = re.compile(
    r"""(?P<quote>['"])\s*(?:%s|%\([A-Za-z_][A-Za-z0-9_]*\)s|\?|:\w+|\$\d+)\s*(?P=quote)"""
)
_SQLALCHEMY_FRAMEWORK = "sqlalchemy"
_DYNAMIC_VALUE = "dynamic-value"
_DYNAMIC_STRUCTURE = "dynamic-structure"


class SqlConcatenationRule(Rule):
    """Detect dynamic strings (f-string, format, concat) passed to `execute`-style cursor calls."""

    ID = "security.sql-concatenation"

    def definition(self) -> RuleDefinition:
        """Describe the SQL-concatenation rule as a medium-confidence warning.

        Medium confidence because ``execute`` is a generic method name and
        non-SQL receivers (Click commands, generic command runners) do
        occasionally surface; the dynamic-first-arg gate keeps the noise
        bounded.

        Returns:
            Definition for the SQL-concatenation rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="SQL concatenation",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``execute``-style calls whose first arg is dynamic, plus over-quoted placeholders.

        Two shapes trigger findings: a dynamic SQL string (f-string,
        ``.format()``, ``%``, ``+``) whose fixed fragments contain SQL; and a
        quoted placeholder (``'?'`` / ``"%s"``) in a parameterised call - the
        quotes break parameter binding by some drivers.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unsafe ``execute`` / ``executemany`` /
            ``executescript`` / ``text`` call.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        return [
            _sql_concatenation_finding(unit, definition, node, target, source_label, message_kind)
            for node, target, source_label, message_kind in _unsafe_sql_calls(unit.tree)
        ]


def _unsafe_sql_calls(tree: ast.AST) -> list[tuple[ast.Call, str, str, str]]:
    constants = module_string_constants(tree)
    sqlalchemy_present = _SQLALCHEMY_FRAMEWORK in frameworks_in_use(tree)
    findings: list[tuple[ast.Call, str, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        candidate = _unsafe_sql_call(node, constants, sqlalchemy_present)
        if candidate is not None:
            findings.append((node, *candidate))
    return findings


def _unsafe_sql_call(
    node: ast.Call,
    constants: dict[str, str],
    sqlalchemy_present: bool,
) -> tuple[str, str, str] | None:
    target = call_target_name(node)
    if target is None:
        return None
    leaf = target.split(".")[-1]
    if leaf not in _SQL_EXECUTE_LEAVES:
        return None
    if leaf == "text" and not sqlalchemy_present:
        return None
    if not node.args:
        return None
    first_arg = node.args[0]
    if is_dynamic_string(first_arg):
        if not _contains_sql_keyword(first_arg, constants):
            return None
        if is_fixed_string_expression(first_arg, constants):
            return None
        return target, "dynamic-sql", _dynamic_message_kind(first_arg, node)
    if _uses_quoted_placeholder_with_parameters(node):
        return target, "quoted-placeholder", _DYNAMIC_VALUE
    return None


def _contains_sql_keyword(node: ast.expr, constants: dict[str, str]) -> bool:
    return any(
        _SQL_KEYWORD_RE.search(fragment) for fragment in fixed_string_fragments(node, constants)
    )


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
    message_kind: str,
) -> Finding:
    if source_label == "quoted-placeholder":
        message = (
            f"`{target}()` manually quotes a SQL placeholder while passing parameters - "
            "leave placeholders unquoted."
        )
        remediation = (
            "Pass placeholders unquoted and keep values in the driver parameter sequence: "
            "``cursor.execute('SELECT * FROM t WHERE id = ?', (id,))``."
        )
    elif message_kind == _DYNAMIC_STRUCTURE:
        message = f"`{target}()` receives dynamic SQL structure - validate SQL fragments."
        remediation = (
            "Whitelist or validate table names, column names, clauses, and placeholder lists. "
            "Keep values parameterised with driver parameters."
        )
    else:
        message = f"`{target}()` receives a dynamic SQL string - use parameterised arguments."
        remediation = (
            "Pass values as a separate parameter sequence: "
            "``cursor.execute('SELECT * FROM t WHERE id = ?', (id,))``."
        )
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
        remediation=remediation,
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


def _dynamic_message_kind(first_arg: ast.expr, call: ast.Call) -> str:
    if not _has_parameter_argument(call):
        return _DYNAMIC_VALUE
    if _has_structure_interpolation(first_arg) and not _has_value_interpolation(first_arg):
        return _DYNAMIC_STRUCTURE
    return _DYNAMIC_VALUE


def _has_value_interpolation(node: ast.expr) -> bool:
    return any(
        _VALUE_INTERPOLATION_CONTEXT_RE.search(context) for context in _interpolation_contexts(node)
    )


def _has_structure_interpolation(node: ast.expr) -> bool:
    return any(
        _STRUCTURE_INTERPOLATION_CONTEXT_RE.search(context)
        for context in _interpolation_contexts(node)
    )


def _interpolation_contexts(node: ast.expr) -> tuple[str, ...]:
    contexts: list[str] = []
    _collect_interpolation_contexts(node, contexts)
    return tuple(contexts)


def _collect_interpolation_contexts(node: ast.expr, contexts: list[str]) -> None:
    if isinstance(node, ast.JoinedStr):
        prefix = ""
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                prefix += value.value
            elif isinstance(value, ast.FormattedValue):
                contexts.append(prefix)
        return
    if isinstance(node, ast.BinOp):
        _collect_interpolation_contexts(node.left, contexts)
        _collect_interpolation_contexts(node.right, contexts)
        return
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        _collect_interpolation_contexts(node.func.value, contexts)
        for arg in node.args:
            _collect_interpolation_contexts(arg, contexts)
        for keyword in node.keywords:
            _collect_interpolation_contexts(keyword.value, contexts)
