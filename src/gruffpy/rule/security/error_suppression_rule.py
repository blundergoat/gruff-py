"""``security.error-suppression`` - wide-exception suppression patterns.

Catches:

- ``contextlib.suppress(Exception)`` / ``suppress(BaseException)``
- ``try: ... except (Exception, BaseException): ...`` - tuple of wide types

Distinct from ``security.silent-except``: that rule needs a pass-only body;
this rule fires on the *type* shape regardless of body, because catching
``Exception``/``BaseException`` is itself a smell.
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
from gruffpy.rule.security._security_node_helper import call_target_name

_WIDE: frozenset[str] = frozenset({"Exception", "BaseException"})
_SOURCE_NEEDLES: tuple[str, ...] = ("Exception", "BaseException")


class ErrorSuppressionRule(Rule):
    """Detect wide-exception suppression via `suppress(Exception)` or a wide-tuple `except`."""

    ID = "security.error-suppression"

    def definition(self) -> RuleDefinition:
        """Describe the wide-error-suppression rule as a medium-confidence advisory.

        Advisory rather than warning because there are legitimate cases
        (top-level event loops, plugin sandboxes) where catching
        ``Exception`` is intentional - narrower than ``BaseException`` and
        well-thought-out.

        Returns:
            Definition for the wide-error-suppression rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Wide error suppression",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag wide-exception suppression *shapes* (regardless of handler body).

        Two shapes trigger findings: ``contextlib.suppress(Exception)`` /
        ``suppress(BaseException)``; and ``except (Exception, ...)`` /
        ``except (BaseException, ...)`` tuple handlers. The plain
        ``except Exception:`` shape with a pass-only body is handled by
        ``security.silent-except`` - this rule complements that one by
        catching the type-shape signal regardless of body.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per wide-suppression shape (``with suppress(...)``
            or wide-tuple ``except``).
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.With):
                findings.extend(self._check_with(definition, unit, node))
            elif isinstance(node, ast.ExceptHandler) and _is_wide_tuple(node):
                findings.append(_build_finding(definition, unit, node, "tuple-wide-except"))
        return findings

    def _check_with(self, definition: RuleDefinition, unit: AnalysisUnit, with_stmt: ast.With) -> list[Finding]:
        """Collect wide-exception suppression findings from a with statement.

        A match requires a target ending in suppress and a bare wide-exception name among positional arguments; the target's owner is not resolved.

        Args:
            definition: Rule identity, severity, and classification to copy into the finding.
            unit: Analysis unit providing the displayed file path.
            with_stmt: With statement whose context-manager calls are inspected.

        Returns:
            One finding per matching context item, or an empty list when none match.
        """
        out: list[Finding] = []
        for item in with_stmt.items:
            if not isinstance(item.context_expr, ast.Call):
                continue
            target = call_target_name(item.context_expr)
            if target is None:
                continue
            leaf = target.split(".")[-1]
            if leaf != "suppress":
                continue
            for arg in item.context_expr.args:
                if isinstance(arg, ast.Name) and arg.id in _WIDE:
                    out.append(_build_finding(definition, unit, with_stmt, f"{target}({arg.id})"))
                    break
        return out


def _is_wide_tuple(handler: ast.ExceptHandler) -> bool:
    """True if the handler catches a tuple including Exception or BaseException.

    Args:
        handler: Exception handler whose tuple elements are checked for bare wide-exception names.

    Returns:
        True when a tuple contains a bare Exception or BaseException name; false otherwise.
    """
    if not isinstance(handler.type, ast.Tuple):
        return False
    return any(isinstance(elt, ast.Name) and elt.id in _WIDE for elt in handler.type.elts)


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    label: str,
) -> Finding:
    """Build a finding for a recognized wide-suppression shape.

    Args:
        definition: Rule identity, severity, and classification to copy into the finding.
        unit: Analysis unit providing the displayed file path.
        node: Matched with statement or exception handler providing the source span.
        label: Suppression shape to include in the message and metadata.

    Returns:
        Finding at the matched node's location with the supplied shape label.
    """
    return Finding(
        rule_id=definition.id,
        message=f"Wide-exception suppression: `{label}`.",
        file_path=unit.file.display_path,
        line=node.lineno,  # type: ignore[attr-defined]  # AST location exists here
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        remediation=("Narrow the exception type or remove the suppression and handle the failure deliberately."),
        secondary_pillars=definition.secondary_pillars,
        metadata={"shape": label},
    )
