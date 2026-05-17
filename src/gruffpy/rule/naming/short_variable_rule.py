"""Single-character variable names outside common idioms.

Allowed by default: ``i``, ``j``, ``k``, ``n``, ``m``, ``x``, ``y``, ``z``,
``e`` (exception), ``_`` (throwaway), ``f`` (file). Configurable via
``acceptedShortNames`` per-rule option.

Scope: local assignments (Assign / AnnAssign). Function parameters are
intentionally NOT scanned — single-char params are common in math-flavoured
code (``def f(x, y, z): ...``) and the parameter rule lives in
``naming.parameter-type-name``. Test files are exempt; assertion fixtures and
table-driven rule tests routinely use tiny local placeholders where this
low-confidence style warning is noisy.
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
        if _is_test_file(unit.file.display_path):
            return []
        definition = self.definition()
        accepted = _accepted_short_names(context, definition)
        return _short_variable_findings(unit, definition, accepted)


def _accepted_short_names(
    context: RuleContext,
    definition: RuleDefinition,
) -> frozenset[str]:
    settings = context.settings_for(definition)
    configured = settings.options.get("acceptedShortNames", list(_DEFAULT_ACCEPTED))
    if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
        configured = list(_DEFAULT_ACCEPTED)
    return frozenset(configured)


def _short_variable_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    accepted: frozenset[str],
) -> list[Finding]:
    assert unit.tree is not None
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()
    for name, lineno in _assigned_names(unit.tree):
        if _should_report_short_name(name, lineno, accepted, seen):
            findings.append(_short_variable_finding(unit, definition, name, lineno))
    return findings


def _assigned_names(tree: ast.AST) -> list[tuple[str, int]]:
    names: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        names.extend(_assignment_names(node))
    return names


def _assignment_names(node: ast.AST) -> list[tuple[str, int]]:
    if isinstance(node, ast.Assign):
        return _assign_target_names(node)
    if isinstance(node, ast.AnnAssign):
        return _target_names(node.target)
    return []


def _assign_target_names(node: ast.Assign) -> list[tuple[str, int]]:
    names: list[tuple[str, int]] = []
    for target in node.targets:
        names.extend(_target_names(target))
    return names


def _target_names(target: ast.AST) -> list[tuple[str, int]]:
    if isinstance(target, ast.Name):
        return [(target.id, target.lineno)]
    if isinstance(target, ast.Tuple | ast.List):
        return [(elt.id, elt.lineno) for elt in target.elts if isinstance(elt, ast.Name)]
    return []


def _should_report_short_name(
    name: str,
    lineno: int,
    accepted: frozenset[str],
    seen: set[tuple[str, int]],
) -> bool:
    if (name, lineno) in seen:
        return False
    if len(name) != 1 or name in accepted:
        return False
    seen.add((name, lineno))
    return True


def _short_variable_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    name: str,
    lineno: int,
) -> Finding:
    return Finding(
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
    )


def _is_test_file(display_path: str) -> bool:
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")
