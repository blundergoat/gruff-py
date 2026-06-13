"""``correctness.unsafe-numeric-coercion`` - int() conversions whose guard does not hold.

Two shapes:

- Guarded-string coercion: ``int(x)`` reachable under an ``x.isnumeric()`` /
  ``x.isdigit()`` guard on the same name - both the direct form
  (``if x.isdigit(): int(x)``, including ternaries) and the early-exit form
  (``if not x.isdigit(): raise ...`` followed by ``int(x)``). Both predicates
  accept characters ``int()`` rejects - ``int("²")`` raises ``ValueError``
  even though ``"²".isnumeric()`` is ``True`` (same for "½" and
  Roman-numeral "Ⅻ").
- Unchecked-float coercion (confined): inside functions whose parameters are
  all untyped, ``object``, or ``Any`` (defensive-coercion signatures),
  ``int(f)`` where ``f`` was assigned ``float(<non-literal>)`` and no
  ``math.isfinite`` check covers ``f`` or its source - ``int(float("nan"))``
  raises ``ValueError`` and ``int(float("inf"))`` raises ``OverflowError``.

Both shapes stay silent when the ``int()`` call sits in the body of a ``try``
whose handlers catch *that conversion's* failures - ``ValueError`` for the
guarded string, both ``ValueError`` and ``OverflowError`` for the unchecked
float - and when ``int`` is rebound at module level. A handler protects only
calls in the ``try`` body, not its ``else`` / ``finally`` clauses (whose
exceptions the handlers never see). Nested ``def`` / ``class`` scopes are
analysed in their own pass, so a function's guards never reach into them.
"""

import ast
from collections.abc import Iterable

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._ast_scope import walk_function_scope, walk_statement_scope
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_GUARD_METHODS: frozenset[str] = frozenset({"isnumeric", "isdigit"})
_VALUE_ERROR = "ValueError"
_OVERFLOW_ERROR = "OverflowError"
# The concrete coercion failures each except-clause name actually catches.
# A guarded string ``int("²")`` raises only ValueError; an unchecked-float
# ``int()`` raises ValueError on nan and OverflowError on inf - so a handler
# protects a conversion only when it covers every failure that conversion can
# raise. ArithmeticError is OverflowError's base but not ValueError's.
_EXCEPTION_COVERAGE: dict[str, frozenset[str]] = {
    "ValueError": frozenset({_VALUE_ERROR}),
    "OverflowError": frozenset({_OVERFLOW_ERROR}),
    "ArithmeticError": frozenset({_OVERFLOW_ERROR}),
    "Exception": frozenset({_VALUE_ERROR, _OVERFLOW_ERROR}),
    "BaseException": frozenset({_VALUE_ERROR, _OVERFLOW_ERROR}),
}
_GUARDED_STRING_EXCEPTIONS: frozenset[str] = frozenset({_VALUE_ERROR})
_UNCHECKED_FLOAT_EXCEPTIONS: frozenset[str] = frozenset({_VALUE_ERROR, _OVERFLOW_ERROR})
_ANY_ANNOTATION_NAMES: frozenset[str] = frozenset({"Any", "object"})
_GUARDED_REMEDIATION = (
    "Convert with try/except ValueError instead of pre-checking: isnumeric() "
    'and isdigit() accept characters int() rejects (superscripts like "²", '
    'fractions like "½", Roman numerals like "Ⅻ").'
)
_FLOAT_REMEDIATION = (
    "Gate the conversion with math.isfinite() or wrap it in "
    'try/except (ValueError, OverflowError): int(float("nan")) raises '
    'ValueError and int(float("inf")) raises OverflowError.'
)


class UnsafeNumericCoercionRule(Rule):
    """Detect int() conversions guarded by isnumeric()/isdigit() or unchecked floats."""

    ID = "correctness.unsafe-numeric-coercion"

    def definition(self) -> RuleDefinition:
        """Describe the unsafe-numeric-coercion rule as a high-confidence advisory.

        Advisory severity per the new-rule rollout policy; high confidence
        because both matched shapes are exact AST patterns with verified
        crash reproductions and the try/except / isfinite escapes are
        honoured before a finding is emitted.

        Returns:
            Definition for the unsafe-numeric-coercion rule under the
            correctness pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Unsafe numeric coercion",
            pillar=Pillar.CORRECTNESS,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag int() conversions whose isnumeric/isdigit or float guard is unsound.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per unsound conversion site.
        """
        if not isinstance(unit.tree, ast.Module) or "int(" not in unit.source:
            return []
        if _has_module_level_int_rebind(unit.tree):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if isinstance(node, (ast.If, ast.IfExp)):
                findings.extend(_guarded_coercion_findings(definition, unit, node))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(_unchecked_float_findings(definition, unit, node))
        findings.extend(_early_exit_guard_findings(definition, unit))
        return _deduplicated(findings)


def _deduplicated(findings: list[Finding]) -> list[Finding]:
    """Drop repeats of the same conversion site.

    The direct-guard, early-exit, and float passes overlap when a conversion
    sits under redundant or nested guards, so the same ``int()`` call can be
    collected more than once. Keying on line span plus message (which encodes
    the converted name and shape) collapses those to one finding.
    """
    seen: set[tuple[int | None, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.line, finding.end_line, finding.message)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _has_module_level_int_rebind(tree: ast.Module) -> bool:
    for node in tree.body:
        for name in _bound_names(node):
            if name == "int":
                return True
    return False


def _bound_names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, (ast.Import, ast.ImportFrom)):
        return [alias.asname or alias.name.split(".")[0] for alias in node.names]
    if isinstance(node, ast.Assign):
        return [target.id for target in node.targets if isinstance(target, ast.Name)]
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def _guarded_coercion_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.If | ast.IfExp,
) -> list[Finding]:
    guards = _guarded_names(node.test)
    if not guards:
        return []
    ascii_guarded = _ascii_guarded_names(node.test)
    guarded_branch = node.body if isinstance(node, ast.If) else [node.body]
    findings: list[Finding] = []
    for branch_node in guarded_branch:
        for call in _coercion_calls(walk_statement_scope(branch_node)):
            name = _single_name_argument(call)
            if name is None or name not in guards or name in ascii_guarded:
                continue
            if _is_protected_by_try(call, _GUARDED_STRING_EXCEPTIONS):
                continue
            findings.append(_guarded_string_finding(definition, unit, call, name, guards[name]))
    return findings


def _early_exit_guard_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
) -> list[Finding]:
    """Catch the early-exit form: ``if not x.isdigit(): raise ...`` then ``int(x)``."""
    findings: list[Finding] = []
    for sequence in _statement_sequences(unit.tree):
        active_guards: dict[str, str] = {}
        for statement in sequence:
            if isinstance(statement, ast.If) and _is_early_exit_guard(statement):
                active_guards.update(_negated_guarded_names(statement.test))
                continue
            for call in _coercion_calls(walk_statement_scope(statement)):
                name = _single_name_argument(call)
                if name is None or name not in active_guards:
                    continue
                if _is_protected_by_try(call, _GUARDED_STRING_EXCEPTIONS):
                    continue
                findings.append(
                    _guarded_string_finding(definition, unit, call, name, active_guards[name])
                )
            for bound in _bound_names(statement):
                active_guards.pop(bound, None)
    return findings


def _statement_sequences(tree: ast.AST | None) -> list[list[ast.stmt]]:
    sequences: list[list[ast.stmt]] = []
    if tree is None:
        return sequences
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            value = getattr(node, field, None)
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                sequences.append(value)
    return sequences


def _is_early_exit_guard(statement: ast.If) -> bool:
    return (
        not statement.orelse
        and bool(statement.body)
        and isinstance(statement.body[-1], (ast.Raise, ast.Return, ast.Continue, ast.Break))
    )


def _negated_guarded_names(test: ast.expr) -> dict[str, str]:
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
        return {}
    ascii_guarded = _ascii_guarded_names(test.operand)
    return {
        name: guard
        for name, guard in _guarded_names(test.operand).items()
        if name not in ascii_guarded
    }


def _guarded_string_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    name: str,
    guard: str,
) -> Finding:
    return _build_finding(
        definition,
        unit,
        call,
        message=(
            f"`int({name})` is guarded by `{name}.{guard}()`, which accepts "
            f'characters int() rejects (e.g. "²") and still crashes; the '
            "conversion needs a try/except ValueError instead."
        ),
        remediation=_GUARDED_REMEDIATION,
        metadata={
            "shape": "guarded-string-coercion",
            "guard": guard,
            "value": name,
        },
    )


def _guarded_names(test: ast.expr) -> dict[str, str]:
    guards: dict[str, str] = {}
    for node in ast.walk(test):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _GUARD_METHODS
            and isinstance(node.func.value, ast.Name)
        ):
            guards[node.func.value.id] = node.func.attr
    return guards


def _ascii_guarded_names(test: ast.expr) -> set[str]:
    """Names carrying an ``.isascii()`` guard in *test*.

    ``s.isdigit()``/``s.isnumeric()`` combined with ``s.isascii()`` admits only
    ASCII digits 0-9, which ``int()`` always accepts - so such a conversion is
    safe and must not be flagged. ``isascii()`` is the canonical fix for this
    rule, so flagging the fixed code would be a false positive.
    """
    names: set[str] = set()
    for node in ast.walk(test):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "isascii"
            and isinstance(node.func.value, ast.Name)
        ):
            names.add(node.func.value.id)
    return names


def _coercion_calls(nodes: Iterable[ast.AST]) -> list[ast.Call]:
    return [
        candidate
        for candidate in nodes
        if isinstance(candidate, ast.Call)
        and isinstance(candidate.func, ast.Name)
        and candidate.func.id == "int"
    ]


def _single_name_argument(call: ast.Call) -> str | None:
    if len(call.args) != 1 or call.keywords:
        return None
    argument = call.args[0]
    if isinstance(argument, ast.Name):
        return argument.id
    return None


def _is_protected_by_try(
    node: ast.AST,
    required: frozenset[str],
    stop_at: ast.AST | None = None,
) -> bool:
    child: ast.AST = node
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None and current is not stop_at:
        # Only the try body is protected: handlers do not catch exceptions
        # raised from the same try's else/finally clauses.
        if (
            isinstance(current, ast.Try)
            and child in current.body
            and _has_protective_handler(current, required)
        ):
            return True
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return False
        child = current
        current = getattr(current, "parent", None)
    return False


def _has_protective_handler(try_node: ast.Try, required: frozenset[str]) -> bool:
    covered: set[str] = set()
    for handler in try_node.handlers:
        if handler.type is None:
            return True
        for name_node in ast.walk(handler.type):
            rightmost = _rightmost_name(name_node)
            if rightmost is not None:
                covered |= _EXCEPTION_COVERAGE.get(rightmost, frozenset())
    return required <= covered


def _rightmost_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _unchecked_float_findings(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[Finding]:
    if not _has_defensive_signature(function):
        return []
    float_sources = _float_assignment_sources(function)
    if not float_sources:
        return []
    finite_checked = _isfinite_argument_names(function)
    findings: list[Finding] = []
    for call in _coercion_calls(walk_function_scope(function)):
        name = _single_name_argument(call)
        if name is None or name not in float_sources:
            continue
        if name in finite_checked or float_sources[name] & finite_checked:
            continue
        if _is_protected_by_try(call, _UNCHECKED_FLOAT_EXCEPTIONS, stop_at=function):
            continue
        findings.append(
            _build_finding(
                definition,
                unit,
                call,
                message=(
                    f"`int({name})` converts a float from a dynamic source without a "
                    'math.isfinite() gate; int(float("nan")) raises ValueError and '
                    'int(float("inf")) raises OverflowError.'
                ),
                remediation=_FLOAT_REMEDIATION,
                metadata={
                    "shape": "unchecked-float-coercion",
                    "value": name,
                },
            )
        )
    return findings


def _has_defensive_signature(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    real_parameters = [
        parameter for parameter in parameters if parameter.arg not in {"self", "cls"}
    ]
    if not real_parameters:
        return False
    return all(_is_defensive_annotation(parameter.annotation) for parameter in real_parameters)


def _is_defensive_annotation(annotation: ast.expr | None) -> bool:
    if annotation is None:
        return True
    rightmost = _rightmost_name(annotation)
    return rightmost in _ANY_ANNOTATION_NAMES


def _isfinite_argument_names(function: ast.AST) -> set[str]:
    """Names passed positionally to an ``isfinite``-style guard in *function*."""
    names: set[str] = set()
    for node in walk_function_scope(function):
        if isinstance(node, ast.Call) and _rightmost_name(node.func) == "isfinite":
            names.update(argument.id for argument in node.args if isinstance(argument, ast.Name))
    return names


def _float_assignment_sources(function: ast.AST) -> dict[str, set[str]]:
    """Map each ``x = float(<non-literal>)`` local to the names in its source expr."""
    sources: dict[str, set[str]] = {}
    for node in walk_function_scope(function):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "float"
            and node.value.args
            and not isinstance(node.value.args[0], ast.Constant)
        ):
            sources[node.targets[0].id] = {
                inner.id for inner in ast.walk(node.value.args[0]) if isinstance(inner, ast.Name)
            }
    return sources


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    *,
    message: str,
    remediation: str,
    metadata: dict[str, str],
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=message,
        file_path=unit.file.display_path,
        line=getattr(node, "lineno", 1),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        remediation=remediation,
        secondary_pillars=definition.secondary_pillars,
        metadata=dict(metadata),
    )
