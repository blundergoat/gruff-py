"""Bool-returning functions / bool-typed attributes should start with a
boolean-intent prefix or predicate spelling: ``is_``, ``has_``, ``can_``,
``uses_``, ``supports_``, ``enabled``, ``include_*``, and similar forms.

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
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule

_BOOLEAN_PREFIXES: frozenset[str] = frozenset(
    {
        "accepts",
        "allows",
        "are",
        "can",
        "check",
        "checks",
        "contains",
        "did",
        "do",
        "does",
        "expects",
        "has",
        "is",
        "matches",
        "must",
        "needs",
        "produces",
        "requires",
        "returns",
        "should",
        "supports",
        "uses",
        "validates",
        "was",
        "will",
    }
)
_BOOLEAN_ADJECTIVES: frozenset[str] = frozenset(
    {
        "active",
        "applicable",
        "available",
        "default",
        "disabled",
        "empty",
        "enabled",
        "excluded",
        "frozen",
        "included",
        "interactive",
        "invalid",
        "optional",
        "present",
        "ready",
        "required",
        "valid",
        "verbose",
        "visible",
    }
)
_BOOLEAN_PREFIX_PATTERNS: tuple[str, ...] = (
    "exclude_",
    "include_",
    "no_",
    "with_",
    "without_",
)
_BOOLEAN_SUFFIX_PATTERNS: tuple[str, ...] = (
    "_bool",
    "_disabled",
    "_enabled",
    "_flag",
    "_optional",
    "_required",
)


class BooleanPrefixRule(Rule):
    """Flag bool-returning functions and bool-typed attributes lacking an `is_`/`has_`-style prefix."""

    ID = "naming.boolean-prefix"

    def definition(self) -> RuleDefinition:
        """Describe the boolean-prefix rule as a medium-confidence advisory.

        Medium confidence: a bool-returning function may use a synonym we
        don't recognise (``valid_``, ``empty_``, ``open_``) and there's no
        runtime check we can do.

        Returns:
            Definition for the boolean-prefix rule under the naming pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Boolean prefix",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag bool-typed functions/attributes without a predicate-shaped name.

        Triggers when the return annotation contains ``bool`` (including
        ``"bool"`` strings and ``Optional[bool]``) or when an annotated
        assignment uses ``bool``, and the name doesn't match an
        ``is_``/``has_``/``can_``/predicate-shape prefix. Test files and
        ``@override`` methods are skipped to avoid forcing renames on
        inherited contracts.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per bool-typed function or attribute lacking a
            boolean-intent name.
        """
        if unit.tree is None:
            return []
        if _is_test_file(unit.file.display_path):
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
    lowered = stripped.lower()
    tokens = lower_tokens(stripped)
    if not tokens:
        return False
    return (
        lowered in _BOOLEAN_PREFIXES
        or lowered in _BOOLEAN_ADJECTIVES
        or tokens[0] in _BOOLEAN_PREFIXES
        or tokens[-1] in _BOOLEAN_ADJECTIVES
        or lowered.startswith(_BOOLEAN_PREFIX_PATTERNS)
        or lowered.endswith(_BOOLEAN_SUFFIX_PATTERNS)
    )


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


def _is_test_file(display_path: str) -> bool:
    normalized = display_path.replace("\\", "/").lower()
    name = normalized.rsplit("/", 1)[-1]
    if normalized.startswith("tests/") or "/tests/" in normalized:
        return True
    return "/" not in normalized and name.startswith("test_") and name.endswith(".py")
