"""Bool-returning functions / bool-typed attributes should start with a
boolean-intent prefix: ``is_``, ``has_``, ``can_``, ``should_``, ``was_``,
``did_``, ``will_``, ``must_``, ``needs_``.

Detection:

- ``def f() -> bool`` / ``def f() -> "bool"`` / ``def f() -> Optional[bool]``
  — return-type annotation contains ``bool``.
- ``x: bool = ...`` — annotated assignment with bool type.

Skip dunder names. Skip method overrides (``@override``) — the prefix is
inherited from the parent class signature.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import _decorator_name
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_BOOLEAN_PREFIXES: frozenset[str] = frozenset(
    {"is", "has", "can", "should", "was", "did", "will", "must", "needs", "are", "do", "does"}
)


class BooleanPrefixRule(Rule):
    ID = "naming.boolean-prefix"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Boolean prefix",
            pillar=Pillar.NAMING,
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
            finding = self._finding_for_node(unit, definition, node)
            if finding is not None:
                findings.append(finding)
        return findings

    def _finding_for_node(
        self,
        unit: AnalysisUnit,
        definition: RuleDefinition,
        node: ast.AST,
    ) -> Finding | None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            return self._function_finding(unit, definition, node)
        if isinstance(node, ast.AnnAssign):
            return self._attribute_finding(unit, definition, node)
        return None

    def _function_finding(
        self,
        unit: AnalysisUnit,
        definition: RuleDefinition,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Finding | None:
        if _is_dunder(node.name) or _has_override_decorator(node):
            return None
        if not _has_bool_return(node) or _has_boolean_prefix(node.name):
            return None
        return self._finding(unit, definition, node.name, node.lineno, kind="function")

    def _attribute_finding(
        self,
        unit: AnalysisUnit,
        definition: RuleDefinition,
        node: ast.AnnAssign,
    ) -> Finding | None:
        if not isinstance(node.target, ast.Name):
            return None
        name = node.target.id
        if _is_dunder(name) or _has_boolean_prefix(name):
            return None
        if not _is_bool_annotation(node.annotation):
            return None
        return self._finding(unit, definition, name, node.target.lineno, kind="attribute")

    def _finding(
        self,
        unit: AnalysisUnit,
        definition: RuleDefinition,
        name: str,
        lineno: int,
        kind: str,
    ) -> Finding:
        return Finding(
            rule_id=definition.id,
            message=(
                f"{kind.capitalize()} {name!r} returns / is bool but lacks a boolean-intent "
                f"prefix (is_, has_, can_, should_, was_, did_, will_, must_, needs_)."
            ),
            file_path=unit.file.display_path,
            line=lineno,
            severity=definition.default_severity,
            pillar=definition.pillar,
            tier=definition.tier,
            confidence=definition.confidence,
            end_line=lineno,
            symbol=name,
            remediation=(
                f"Rename {name!r} with a boolean prefix (e.g. ``is_{_strip_lead(name)}``)."
            ),
            secondary_pillars=definition.secondary_pillars,
            metadata={"identifier": name, "kind": kind},
        )


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__") and len(name) > 4


def _has_override_decorator(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(_decorator_name(d).split(".")[-1] == "override" for d in fn.decorator_list)


def _has_boolean_prefix(name: str) -> bool:
    stripped = name.lstrip("_")
    if not stripped:
        return False
    if "_" not in stripped:
        return stripped.lower() in _BOOLEAN_PREFIXES
    first = stripped.split("_", 1)[0]
    return first.lower() in _BOOLEAN_PREFIXES


def _has_bool_return(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    ret = fn.returns
    if ret is None:
        return False
    return _is_bool_annotation(ret)


def _is_bool_annotation(annotation: ast.expr) -> bool:
    if _is_bool_name(annotation):
        return True
    if isinstance(annotation, ast.Constant) and annotation.value == "bool":
        return True
    return any(_is_bool_name(child) for child in ast.walk(annotation))


def _is_bool_name(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "bool"


def _strip_lead(name: str) -> str:
    return name.lstrip("_") or name
