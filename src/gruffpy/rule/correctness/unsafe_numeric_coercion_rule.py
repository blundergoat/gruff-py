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

    The direct-guard and early-exit passes overlap when a conversion sits under redundant or nested guards, or under both an early-exit guard and a
    direct guard, so the same int() call can be collected more than once. Keying on line span plus message, which encodes the converted name, the
    guard method, and the shape, collapses those to one finding.

    Args:
        findings: Findings collected from the direct-guard, unchecked-float, and early-exit passes, in collection order.

    Returns:
        The findings with only the first occurrence of each line, end line, and message key kept, in their original order.
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
    """Report whether a top-level module statement binds the name int, which silences the rule for the whole file.

    Only direct statements of the module body are checked, so a def, class, import alias, or plain or annotated assignment named int counts, while a
    binding inside a function or nested under a module-level if or try does not.

    Args:
        tree: Parsed module whose top-level statements are inspected.

    Returns:
        True when a top-level statement binds int, in which case analyse returns no findings for the file; False otherwise.
    """
    for node in tree.body:
        for name in _bound_names(node):
            if name == "int":
                return True
    return False


def _bound_names(node: ast.stmt) -> list[str]:
    """List the names one statement binds directly, used to detect int rebinding and to expire early-exit guards.

    Covers def, async def, and class names, import aliases (the top-level package for an unaliased dotted import), and bare-name targets of plain and
    annotated assignments. Tuple targets, augmented assignments, for loops, with statements, and walrus bindings contribute nothing.

    Args:
        node: Statement whose direct bindings are read.

    Returns:
        Names bound by the statement; empty for any other statement kind.
    """
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
    """Flag int(name) in the true branch of an if or ternary whose test calls isnumeric() or isdigit() on name.

    Only the true branch is searched (the if body, or the ternary's body expression); the else branch is ignored, and nested def, class, and lambda
    scopes in the branch are not descended into. A name that also has an isascii() call in the same test is exempt, as is a conversion inside the body
    of an enclosing try, up to the nearest function or the module, whose handlers cover ValueError.

    Args:
        definition: Rule definition stamped on each finding.
        unit: Analysed file that supplies the finding's display path.
        node: If statement or conditional expression whose test is searched for guard method calls.

    Returns:
        One guarded-string finding per unprotected conversion of a guarded name; empty when the test calls no guard method.
    """
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
    """Catch the early-exit form: ``if not x.isdigit(): raise ...`` then ``int(x)``.

    Args:
        definition: Rule definition stamped on each finding.
        unit: Analysed file whose whole tree is scanned for statement lists.

    Returns:
        Guarded-string findings for conversions of a name in later statements of the same statement list as a negated early-exit guard on that name,
        up to and including the first later statement that _bound_names reports as binding it. Which tests count as guards follows
        _negated_guarded_names, which bindings end a guard follows _bound_names, and try protection follows _is_protected_by_try. Conversions inside
        nested def, async def, class or lambda bodies, and in a later if that itself has the early-exit shape, are not reported here; a conversion
        guarded in both an enclosing and a nested statement list is returned once per list.
    """
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
                findings.append(_guarded_string_finding(definition, unit, call, name, active_guards[name]))
            for bound in _bound_names(statement):
                active_guards.pop(bound, None)
    return findings


def _statement_sequences(tree: ast.AST | None) -> list[list[ast.stmt]]:
    """Collect every non-empty statement list in the tree so the early-exit pass can scan statements in order.

    Reads the body, orelse, and finalbody fields of every node, which includes module, function, class, loop, if, try, except-handler, with, and
    match-case bodies; expression-valued fields such as a ternary's branches are skipped.

    Args:
        tree: Module tree to search; None produces no sequences.

    Returns:
        Each statement list in ast.walk order; empty when tree is None.
    """
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
    """Report whether an if statement has no else branch and ends its body with raise, return, continue, or break.

    Only the statement's shape is checked; whether its test is a negated guard is decided separately by _negated_guarded_names.

    Args:
        statement: If statement that may open an early-exit guard.

    Returns:
        True when the statement has no else or elif branch and its last body statement exits; False otherwise.
    """
    return not statement.orelse and bool(statement.body) and isinstance(statement.body[-1], (ast.Raise, ast.Return, ast.Continue, ast.Break))


def _negated_guarded_names(test: ast.expr) -> dict[str, str]:
    """Map each name guarded by a negated isnumeric() or isdigit() test to its guard method, for early-exit guards.

    The test qualifies only when its outermost node is a not operation; every guard call inside the negated operand is then mapped, whatever and or or
    operators join them. Names that also have an isascii() call inside the operand are dropped because that combination admits only ASCII digits.

    Args:
        test: Condition of an early-exit if statement.

    Returns:
        Name to guard method (isnumeric or isdigit) for each guarded name; empty when the outermost node of the test is not a not operation.
    """
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
        return {}
    ascii_guarded = _ascii_guarded_names(test.operand)
    return {name: guard for name, guard in _guarded_names(test.operand).items() if name not in ascii_guarded}


def _guarded_string_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    name: str,
    guard: str,
) -> Finding:
    """Build the guarded-string finding for one int(name) conversion, citing the guard method in its message.

    Args:
        definition: Rule definition stamped on the finding.
        unit: Analysed file that supplies the finding's display path.
        call: The int() call whose line span locates the finding.
        name: Variable passed to int(), quoted in the message and recorded as the value metadata.
        guard: Guard method, isnumeric or isdigit, that the message cites and the metadata records.

    Returns:
        Finding with the guarded-string remediation and metadata recording shape guarded-string-coercion, the guard method, and the value name.
    """
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
    """Map each name whose isnumeric() or isdigit() method is called anywhere in a test to that method name.

    The receiver must be a bare name, so attribute receivers such as self.value.isdigit() are ignored. Negation and boolean operators are not
    considered, and when one name is called with both methods the one ast.walk visits last wins.

    Args:
        test: Condition expression to search.

    Returns:
        Name to guard method mapping; empty when the test calls neither method on a bare name.
    """
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

    Args:
        test: Condition expression searched for isascii() calls.

    Returns:
        Bare names whose isascii() method is called anywhere in the test, which callers exempt from guard findings; empty when there is none.
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
    """Select the calls to the bare name int from a sequence of nodes.

    Args:
        nodes: AST nodes to filter, usually from a scope-bounded walk of a statement or function.

    Returns:
        The int() calls in input order; calls through an attribute such as builtins.int are excluded.
    """
    return [
        candidate for candidate in nodes if isinstance(candidate, ast.Call) and isinstance(candidate.func, ast.Name) and candidate.func.id == "int"
    ]


def _single_name_argument(call: ast.Call) -> str | None:
    """Return the variable an int() call converts when it takes exactly one positional bare-name argument.

    Args:
        call: The int() call to inspect.

    Returns:
        The argument's name, or None when the call passes keywords such as base, has other than one positional argument, or converts a non-name
        expression.
    """
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
    """Report whether a node sits in the body of an enclosing try whose handlers catch every required exception.

    Walks parent links upward from the node. A try protects only when the walk reaches it from one of its direct body statements, so a conversion in
    its handlers, else, or finally clause is not protected by that try, though an outer try may still protect it. The walk ends without protection at
    the nearest enclosing function or the module, or on reaching stop_at.

    Args:
        node: The int() call whose enclosing try statements are checked.
        required: Exception names the handlers must cover together: ValueError for a guarded string, ValueError and OverflowError for an unchecked
            float.
        stop_at: Node at which the upward walk ends without protection; None leaves the nearest enclosing function or the module as the only limit.

    Returns:
        True when a protecting try body encloses the node; False otherwise.
    """
    child: ast.AST = node
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None and current is not stop_at:
        # Only the try body is protected: handlers do not catch exceptions
        # raised from the same try's else/finally clauses.
        if isinstance(current, ast.Try) and child in current.body and _has_protective_handler(current, required):
            return True
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            return False
        child = current
        current = getattr(current, "parent", None)
    return False


def _has_protective_handler(try_node: ast.Try, required: frozenset[str]) -> bool:
    """Report whether a try statement's except clauses together catch every exception in the required set.

    A bare except protects immediately. Otherwise every name in each handler type, including tuple members and dotted names read by their last
    segment, adds the failures _EXCEPTION_COVERAGE lists for it; names outside that table add nothing.

    Args:
        try_node: Try statement whose except clauses are inspected.
        required: Exception names the conversion can raise.

    Returns:
        True when a bare except exists or the covered failures include every required name; False otherwise.
    """
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
    """Return the last identifier of a name or dotted attribute, such as isfinite for math.isfinite.

    Args:
        node: Expression to read, typically a callee, a parameter annotation, or an exception type.

    Returns:
        The attribute or name identifier; None for any other node kind, such as a subscript, call, or string constant.
    """
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
    """Flag int() of a float(<non-literal>) local in a defensive-signature function without an isfinite check.

    The function is skipped unless _has_defensive_signature accepts it. A conversion is exempt when isfinite() is called anywhere in the function's
    own scope, before or after the conversion, on the converted name or on any name in its float() source expression, or when it sits in a try body
    inside the function whose handlers together cover ValueError and OverflowError. Nested def, class, and lambda bodies are not searched; each nested
    function gets its own pass.

    Args:
        definition: Rule definition stamped on each finding.
        unit: Analysed file that supplies the finding's display path.
        function: Function definition whose own scope is checked.

    Returns:
        One unchecked-float finding per unprotected conversion; empty when the signature is not defensive or no float() local exists.
    """
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
    """Report whether a function has at least one parameter and every parameter is unannotated, object, or Any.

    Positional-only, regular, and keyword-only parameters are counted, excluding ones named self or cls; *args and **kwargs are not considered. This
    is the signature shape the unchecked-float pass requires.

    Args:
        function: Function definition whose parameters are inspected.

    Returns:
        True when at least one counted parameter exists and all counted parameters have a defensive annotation; False otherwise, including for
        functions with no counted parameters.
    """
    parameters = [
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ]
    real_parameters = [parameter for parameter in parameters if parameter.arg not in {"self", "cls"}]
    if not real_parameters:
        return False
    return all(_is_defensive_annotation(parameter.annotation) for parameter in real_parameters)


def _is_defensive_annotation(annotation: ast.expr | None) -> bool:
    """Report whether a parameter annotation is absent or names Any or object.

    Args:
        annotation: Parameter annotation; None means the parameter is unannotated.

    Returns:
        True for no annotation or a name or dotted name ending in Any or object, such as typing.Any; False otherwise, including subscripted and string
        annotations.
    """
    if annotation is None:
        return True
    rightmost = _rightmost_name(annotation)
    return rightmost in _ANY_ANNOTATION_NAMES


def _isfinite_argument_names(function: ast.AST) -> set[str]:
    """Names passed positionally to an ``isfinite``-style guard in *function*.

    Args:
        function: Function node whose own scope is searched; nested def, class, and lambda bodies are excluded.

    Returns:
        Bare names passed positionally to any call whose callee name or last attribute is isfinite; empty when there is none.
    """
    names: set[str] = set()
    for node in walk_function_scope(function):
        if isinstance(node, ast.Call) and _rightmost_name(node.func) == "isfinite":
            names.update(argument.id for argument in node.args if isinstance(argument, ast.Name))
    return names


def _float_assignment_sources(function: ast.AST) -> dict[str, set[str]]:
    """Map each ``x = float(<non-literal>)`` local to the names in its source expr.

    Args:
        function: Function node whose own scope is searched; nested def, class, and lambda bodies are excluded.

    Returns:
        Each assigned name mapped to the set of names in float()'s first argument, which is empty when that argument contains no names; only single
        bare-name targets of plain assignments count, a later qualifying assignment to the same name replaces an earlier one's sources, while any
        other later assignment to that name leaves the entry in place, and the mapping is empty when no such assignment exists.
    """
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
            sources[node.targets[0].id] = {inner.id for inner in ast.walk(node.value.args[0]) if isinstance(inner, ast.Name)}
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
    """Build a finding at a node's line span using the rule definition's severity, pillar, tier, and confidence.

    Args:
        definition: Supplies the rule ID, default severity, pillar, tier, confidence, and secondary pillars.
        unit: Analysed file whose display path is recorded.
        node: AST node the finding points at; the line falls back to 1 and the end line to None when the node has no position.
        message: Finding message naming the converted value and the unsafe shape.
        remediation: Fix guidance attached to the finding.
        metadata: Shape details copied into the finding, so later changes to the caller's dict do not reach it.

    Returns:
        Finding for the rule at the node's line span in the unit's file, carrying the message, remediation, and a copy of the metadata.
    """
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
