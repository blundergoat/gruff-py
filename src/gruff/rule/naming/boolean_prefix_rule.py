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

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule._python_dynamism import _decorator_name
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule

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
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                if _is_dunder(node.name):
                    continue
                if _has_override_decorator(node):
                    continue
                if not _returns_bool(node):
                    continue
                if _has_boolean_prefix(node.name):
                    continue
                findings.append(
                    self._finding(unit, definition, node.name, node.lineno, kind="function"),
                )
            elif (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and _annotation_is_bool(node.annotation)
                and not _has_boolean_prefix(node.target.id)
                and not _is_dunder(node.target.id)
            ):
                findings.append(
                    self._finding(
                        unit, definition, node.target.id, node.target.lineno, kind="attribute"
                    )
                )
        return findings

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


def _returns_bool(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    ret = fn.returns
    if ret is None:
        return False
    return _annotation_is_bool(ret)


def _annotation_is_bool(annotation: ast.expr) -> bool:
    if isinstance(annotation, ast.Name) and annotation.id == "bool":
        return True
    if isinstance(annotation, ast.Constant) and annotation.value == "bool":
        return True
    if isinstance(annotation, ast.Subscript):
        # Optional[bool], Union[bool, None], etc.
        for child in ast.walk(annotation):
            if isinstance(child, ast.Name) and child.id == "bool":
                return True
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        for child in ast.walk(annotation):
            if isinstance(child, ast.Name) and child.id == "bool":
                return True
    return False


def _strip_lead(name: str) -> str:
    return name.lstrip("_") or name
