"""``security.error-suppression`` — wide-exception suppression patterns.

Catches:

- ``contextlib.suppress(Exception)`` / ``suppress(BaseException)``
- ``try: ... except (Exception, BaseException): ...`` — tuple of wide types

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


class ErrorSuppressionRule(Rule):
    ID = "security.error-suppression"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Wide error suppression",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.With):
                findings.extend(self._check_with(definition, unit, node))
            elif isinstance(node, ast.ExceptHandler) and _is_wide_tuple(node):
                findings.append(_build_finding(definition, unit, node, "tuple-wide-except"))
        return findings

    def _check_with(
        self, definition: RuleDefinition, unit: AnalysisUnit, with_stmt: ast.With
    ) -> list[Finding]:
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
    """True if the handler catches a tuple including Exception or BaseException."""
    if not isinstance(handler.type, ast.Tuple):
        return False
    return any(isinstance(elt, ast.Name) and elt.id in _WIDE for elt in handler.type.elts)


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    label: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=f"Wide-exception suppression: `{label}`.",
        file_path=unit.file.display_path,
        line=node.lineno,  # type: ignore[attr-defined]
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        remediation=(
            "Narrow the exception type or remove the suppression and handle "
            "the failure deliberately."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"shape": label},
    )
