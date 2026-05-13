"""Single-character variable names outside common idioms.

Allowed by default: ``i``, ``j``, ``k``, ``n``, ``m``, ``x``, ``y``, ``z``,
``e`` (exception), ``_`` (throwaway), ``f`` (file). Configurable via
``acceptedShortNames`` per-rule option.

Scope: local assignments (Assign / AnnAssign). Function parameters are
intentionally NOT scanned — single-char params are common in math-flavoured
code (``def f(x, y, z): ...``) and the parameter rule lives in
``naming.parameter-type-name``.
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

_DEFAULT_ACCEPTED: tuple[str, ...] = ("i", "j", "k", "n", "m", "x", "y", "z", "e", "_", "f")


class ShortVariableRule(Rule):
    ID = "naming.short-variable"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Short variable name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
            default_options={"acceptedShortNames": list(_DEFAULT_ACCEPTED)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        configured = settings.options.get("acceptedShortNames", list(_DEFAULT_ACCEPTED))
        if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
            configured = list(_DEFAULT_ACCEPTED)
        accepted = frozenset(configured)

        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for node in ast.walk(unit.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._maybe_emit(
                            target.id, target.lineno, accepted, definition, unit, findings, seen
                        )
                    elif isinstance(target, ast.Tuple | ast.List):
                        for elt in target.elts:
                            if isinstance(elt, ast.Name):
                                self._maybe_emit(
                                    elt.id, elt.lineno, accepted, definition, unit, findings, seen
                                )
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                self._maybe_emit(
                    node.target.id, node.target.lineno, accepted, definition, unit, findings, seen
                )
        return findings

    def _maybe_emit(
        self,
        name: str,
        lineno: int,
        accepted: frozenset[str],
        definition: RuleDefinition,
        unit: AnalysisUnit,
        findings: list[Finding],
        seen: set[tuple[str, int]],
    ) -> None:
        if (name, lineno) in seen:
            return
        if len(name) != 1:
            return
        if name in accepted:
            return
        seen.add((name, lineno))
        findings.append(
            Finding(
                rule_id=definition.id,
                message=f"Variable {name!r} is single-character; prefer a descriptive name.",
                file_path=unit.file.display_path,
                line=lineno,
                severity=definition.default_severity,
                pillar=definition.pillar,
                tier=definition.tier,
                confidence=definition.confidence,
                end_line=lineno,
                symbol=name,
                remediation=f"Rename {name!r} or add it to ``acceptedShortNames`` if intentional.",
                secondary_pillars=definition.secondary_pillars,
                metadata={"identifier": name},
            ),
        )
