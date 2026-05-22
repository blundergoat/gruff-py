"""``security.django-mark-safe`` — Django XSS opt-out applied to dynamic content.

Django's ``mark_safe()`` (and the related ``SafeString``, ``SafeText``,
``format_html``) tell the template engine to skip auto-escaping. Calling
them on a string literal is fine (the developer is opting out for a known
trusted constant); calling them on a variable, an f-string, or a
``.format()`` result is an XSS sink — every value flowing in is rendered
without escaping.

Matched shapes (Django framework gate required):

- ``mark_safe(<non-literal>)``
- ``SafeString(<non-literal>)``
- ``SafeText(<non-literal>)``
- ``format_html(<non-literal-template>, ...)``

Calls whose first argument is a plain string literal (``mark_safe("<br>")``)
or an explicit escape-returning call (``mark_safe(escape(x))``) are skipped.
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
    is_string_literal,
)

_DJANGO_GATE: frozenset[str] = frozenset({"django"})
_MARK_SAFE_LEAVES: frozenset[str] = frozenset(
    {"mark_safe", "SafeString", "SafeText", "format_html"}
)
_SOURCE_NEEDLES: tuple[str, ...] = ("mark_safe", "SafeString", "SafeText", "format_html")
_ESCAPE_LEAVES: frozenset[str] = frozenset({"escape", "conditional_escape"})
_REMEDIATION = (
    "Either keep `mark_safe` arguments as plain string literals, or call "
    "`django.utils.html.escape()` / `conditional_escape()` on user-controlled "
    "values before marking them safe. For HTML templating with safe escaping, "
    "use `format_html('<b>{}</b>', value)` (literal template, escaped args)."
)


class DjangoMarkSafeRule(Rule):
    """Detect Django XSS opt-out calls applied to non-literal content."""

    ID = "security.django-mark-safe"

    def definition(self) -> RuleDefinition:
        """Describe the Django mark-safe rule as a medium-confidence WARNING.

        WARNING severity because the call may be legitimate when the input
        is provably escaped (e.g. ``escape(x)`` chain); medium confidence
        because the rule cannot prove the upstream provenance of the value
        being marked safe — only the syntactic absence of a literal or
        escape call.

        Returns:
            Definition for the Django mark-safe rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Django mark_safe on dynamic content",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag mark_safe / SafeString / SafeText / format_html on non-literal input.

        Gated to files importing Django. Skips calls whose first argument
        is a plain string literal or a call to ``escape`` /
        ``conditional_escape`` (both produce strings the developer has
        explicitly escaped).

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per unsafe mark-safe-family call.
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
            leaf = _mark_safe_leaf(node)
            if leaf is None or not node.args:
                continue
            if _has_safe_first_arg(node.args[0]):
                continue
            findings.append(_build_finding(definition, unit, node, leaf))
        return findings


def _mark_safe_leaf(call: ast.Call) -> str | None:
    target = call_target_name(call)
    if target is None:
        return None
    leaf = target.split(".")[-1]
    if leaf not in _MARK_SAFE_LEAVES:
        return None
    return leaf


def _has_safe_first_arg(first: ast.expr) -> bool:
    if is_string_literal(first):
        return True
    if isinstance(first, ast.Call):
        target = call_target_name(first)
        if target is not None and target.split(".")[-1] in _ESCAPE_LEAVES:
            return True
    return False


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    leaf: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"`{leaf}(...)` applied to non-literal content — XSS risk if the "
            "value is user-controlled."
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
            "leaf": leaf,
            **finding_security_metadata(
                definition.id,
                source_label="user-html-input",
                sink_label="django-safe-marker",
            ),
        },
    )
