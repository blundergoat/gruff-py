"""``security.django-raw-sql`` - Django ORM SQL escape hatches with dynamic strings.

The Django ORM's parameterised query paths are safe by default. The escape
hatches - ``QuerySet.raw()``, ``django.db.models.expressions.RawSQL()`` -
accept raw SQL strings; using them with a dynamic string (f-string,
``.format()``, ``%`` formatting, ``+`` concat) reintroduces classic
SQL-injection risk.

``cursor.execute(<dynamic>)`` is intentionally not duplicated here - it is
covered by ``security.sql-concatenation``. ``QuerySet.extra()`` is out of
scope for v1 (the SQL injection vectors live inside ``select`` /
``where`` / ``tables`` collections, which need a different match shape).
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
from gruffpy.rule.security._security_metadata import finding_security_metadata
from gruffpy.rule.security._security_node_helper import (
    call_target_name,
    frameworks_in_use,
    is_dynamic_string,
)

_DJANGO_GATE: frozenset[str] = frozenset({"django"})
_SOURCE_NEEDLES: tuple[str, ...] = (".raw", "RawSQL")
_REMEDIATION = (
    "Pass values as parameters: `Model.objects.raw('SELECT * FROM t WHERE "
    "id = %s', [user_id])`. For aggregations, use `RawSQL('expr = %s', "
    "[value])` or the typed expression API instead of building SQL strings."
)


class DjangoRawSqlRule(Rule):
    """Detect Django ``.raw(...)`` / ``RawSQL(...)`` with dynamic SQL strings."""

    ID = "security.django-raw-sql"

    def definition(self) -> RuleDefinition:
        """Describe the Django raw-SQL rule as a high-confidence WARNING.

        WARNING severity because the call is sometimes legitimate when the
        dynamic component is a hardcoded identifier (column name from a
        whitelist); high confidence because the matched shapes are the
        explicit ORM escape hatches and the dynamic-string first-arg gate
        keeps the FP rate bounded.

        Returns:
            Definition for the Django raw-SQL rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Django raw SQL with dynamic string",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``.raw(<dynamic>)`` and ``RawSQL(<dynamic>, ...)`` in Django files.

        Reuses the ``is_dynamic_string`` helper from sql-concatenation so
        the dynamic-detection logic stays consistent. Files without a
        Django import are skipped entirely (framework gate).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unsafe raw-SQL escape-hatch call.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        if not (frameworks_in_use(unit.tree) & _DJANGO_GATE):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            label = _raw_sql_label(node)
            if label is None or not node.args:
                continue
            if not is_dynamic_string(node.args[0]):
                continue
            findings.append(_build_finding(definition, unit, node, label))
        return findings


def _raw_sql_label(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute) and call.func.attr == "raw":
        return ".raw"
    target = call_target_name(call)
    if target is None:
        return None
    if target.split(".")[-1] == "RawSQL":
        return "RawSQL"
    return None


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    label: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"`{label}(...)` receives a dynamic SQL string - use parameterised arguments instead."
        ),
        file_path=unit.file.display_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "shape": label,
            **finding_security_metadata(
                definition.id,
                source_label="dynamic-sql",
                sink_label="django-orm-raw",
            ),
        },
    )
