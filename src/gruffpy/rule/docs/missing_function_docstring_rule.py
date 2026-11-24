"""Flag functions and methods missing a docstring during `gruff-py analyse` and `hook` runs.

Use this rule so reviewers and agents know each callable's contract without reconstructing edge cases from the body.
Every finding tells the developer only the sections that callable actually needs (intent, parameters, Returns/Yields, and Raises).

- Always exempt: dunder methods, abstract methods, `@typing.overload` stubs, protocol stubs, property setters/deleters, and single-callsite closures.
- Default scope (`everyCallable: true`): production and helper callables emit `warning`, while `test_*` functions in test files emit `advisory`.
- Narrow scope (`everyCallable: false`): limits findings to public callables and skips underscore-private helpers and `test_*` functions.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    is_abstract_method,
    is_overload_stub,
    is_protocol_method_stub,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import extract_docstring
from gruffpy.rule.docs._helpers import (
    EVERY_CALLABLE_OPTION,
    every_callable_enabled,
    has_none_only_return,
    has_raise_in_body,
    has_return_annotation,
    is_generator,
    is_in_documentation_scope,
    is_property_setter_or_deleter,
    is_test_file,
    quoted_names,
    returns_value,
    signature_param_names,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class MissingFunctionDocstringRule(Rule):
    """Detect functions and methods that lack a docstring describing their contract.

    The analyser runs this rule on every parsed Python file and tailors each finding message to the function's real signature and body.
    Missing `test_*` docstrings stay visible at `advisory` severity under `everyCallable: true` so they never trip default `--fail-on warning` gates.
    """

    ID = "docs.missing-function-docstring"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry, `list-rules`, and report formatters.

        Returns:
            Definition for the missing function docstring rule, with `everyCallable` enabled by default.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing function docstring",
            description=(
                "Flags a public function or method with no docstring; with `everyCallable`, also underscore-private "
                "functions and methods (warning) and `test_*` functions in test files (advisory)."
            ),
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_options={EVERY_CALLABLE_OPTION: True},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Inspect one parsed Python module for undocumented functions and methods in the configured scope.

        Called by the analysis runner during `analyse`, `summary`, `report`, and `hook` scans after AST parsing completes.

        Args:
            unit: Parsed source file to inspect; `unit.tree` is None for non-Python files, syntax errors, or budget-skipped files.
            context: Rule execution context supplying the user's `everyCallable` setting.

        Returns:
            Findings for in-scope functions missing docstrings; an empty list when the AST is absent or every callable is documented or exempt.
        """
        # Skip non-Python files, syntax failures, and deep-scan budget skips because no AST is available.
        if unit.tree is None:
            return []
        definition = self.definition()
        every_callable = every_callable_enabled(context, definition)
        return [
            _missing_function_docstring_finding(unit, definition, node, parents)
            for node, parents in _undocumented_functions(unit, every_callable=every_callable)
        ]


def _undocumented_functions(unit: AnalysisUnit, *, every_callable: bool) -> list[tuple[FunctionNode, list[ast.AST]]]:
    """Collect every function and method in the parsed module that should be reported as missing a docstring.

    Walks nested definitions alongside top-level callables and keeps each parent chain so finding generation can format dotted symbol names.

    Args:
        unit: Analysis unit whose parsed tree is walked; `unit.tree` must not be None, and `display_path` identifies test files.
        every_callable: Whether user config includes private names and `test_*` functions in test files.

    Returns:
        Pairs of reportable function nodes and their parent chains in walk order; an empty list when every callable is documented or exempt.

    Raises:
        AssertionError: When `unit.tree` is None (prevented by the guard in `analyse`).
    """
    assert unit.tree is not None
    candidates: list[tuple[FunctionNode, list[ast.AST]]] = []
    # Walk the entire module tree so methods and multi-use inner helpers receive the same check as top-level functions.
    for node in ast.walk(unit.tree):
        # Ignore non-callable AST nodes while walking the module.
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        parents = parent_chain(node)
        # Keep only callables that are in configured scope, lack a docstring, and fail every exemption.
        if _should_report_missing_function_docstring(node, parents, unit.file.display_path, every_callable=every_callable):
            candidates.append((node, parents))
    return candidates


def _should_report_missing_function_docstring(
    node: FunctionNode,
    parents: list[ast.AST],
    display_path: str,
    *,
    every_callable: bool,
) -> bool:
    """Check whether one function or method is in scope, lacks a docstring, and matches no exemption.

    Keeps boilerplate stubs (abstract methods, overloads, property setters/deleters, protocol stubs, single-use closures) out of developer reports.

    Args:
        node: Callable definition whose name, existing docstring, and exemption markers are checked.
        parents: Parent chain from module down to immediate parent, used for protocol-stub and nested-closure checks.
        display_path: Relative file path used to recognize pytest-style `test_*` functions inside test files.
        every_callable: True includes private helpers and `test_*` functions; False limits findings to public non-test callables.

    Returns:
        True when the callable should emit a finding; False when out of scope, already documented, or exempt.
    """
    # Skip dunder methods always, and skip `_private` helpers when the user disabled `everyCallable`.
    if not is_in_documentation_scope(node.name, every_callable=every_callable):
        return False
    # When the user opts out of `everyCallable`, pytest `test_*` functions stay silent in test files.
    if not every_callable and node.name.startswith("test_") and is_test_file(display_path):
        return False
    return not (
        extract_docstring(node) is not None
        or is_abstract_method(node)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
        or is_protocol_method_stub(node, parents)
        or _is_single_callsite_closure(node, parents)
    )


def _is_single_callsite_closure(node: FunctionNode, parents: list[ast.AST]) -> bool:
    """Check whether a nested helper is referenced at most once inside its enclosing function.

    Lets developers write short one-shot callbacks or sort keys inside a function without adding ceremonial docstrings.

    Args:
        node: Function being checked; references inside its own body are ignored.
        parents: Parent chain from module down to immediate parent; the innermost enclosing function defines the search scope.

    Returns:
        True when an enclosing function exists and references `node.name` at most once outside `node`; False for top-level/class methods or reused
        helpers.
    """
    enclosing = next(
        (ancestor for ancestor in reversed(parents) if isinstance(ancestor, ast.FunctionDef | ast.AsyncFunctionDef)),
        None,
    )
    # Top-level functions and ordinary class methods have no enclosing function, so they are never single-callsite closures.
    if enclosing is None:
        return False
    return _name_reference_count_excluding(enclosing, node.name, node) <= 1


def _name_reference_count_excluding(root: ast.AST, name: str, exclude: ast.AST) -> int:
    """Count bare-name references to a nested function inside its enclosing function, skipping the nested body itself.

    Every `ast.Name` context counts (loads and bindings), while attribute accesses such as `obj.name` do not.

    Args:
        root: Enclosing function AST whose descendants are walked.
        name: Nested function name to count.
        exclude: Nested function AST node skipped along with its entire subtree.

    Returns:
        Count of bare-name references outside the nested function; zero when unused or only called via decorators/return values.
    """
    count = 0
    stack: list[ast.AST] = list(ast.iter_child_nodes(root))
    # Walk iteratively so deeply nested helper functions do not hit recursion limits while counting call sites.
    while stack:
        current = stack.pop()
        # Recursive references inside the closure do not count as external uses.
        if current is exclude:
            continue
        # Count each bare identifier match in the enclosing scope to tell one-shot helpers from reused ones.
        if isinstance(current, ast.Name) and current.id == name:
            count += 1
        stack.extend(ast.iter_child_nodes(current))
    return count


def _missing_function_docstring_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: FunctionNode,
    parents: list[ast.AST],
) -> Finding:
    """Build one missing-docstring finding spanning the callable's lines, picking `advisory` severity for `test_*` functions.

    Keeps test-function docstring nudges visible in `gruff-py analyse` and `summary` without breaking `--fail-on warning` CI gates.

    Args:
        unit: Analysis unit supplying the display path and deciding whether `test_*` functions downgrade to `advisory`.
        definition: Rule metadata providing rule ID, default severity, pillar, tier, confidence, and secondary pillars.
        node: Undocumented function or async function whose start and end lines locate the finding.
        parents: Enclosing AST nodes used to build the dotted qualified symbol shown in CLI and JSON output.

    Returns:
        Finding naming the callable's qualified symbol and listing only the docstring sections that callable requires.
    """
    symbol = qualified_symbol(node, parents)
    # Report missing docstrings on pytest `test_*` functions at advisory severity so default warning gates focus on production and helper code.
    severity = Severity.ADVISORY if node.name.startswith("test_") and is_test_file(unit.file.display_path) else definition.default_severity
    return Finding(
        rule_id=definition.id,
        message=_missing_docstring_message(node, symbol),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=(
            "Summarise the function's contract: what it does, what it returns at the edge, "
            "and what the caller must satisfy. Describe behaviour, not the signature."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )


def _missing_docstring_message(node: FunctionNode, symbol: str) -> str:
    """Tailor the finding message to the callable's signature and body so developers are only asked for applicable sections.

    Args:
        node: Undocumented function node whose parameters, return behaviour, and raise statements are inspected.
        symbol: Qualified symbol rendered in the developer-facing message.

    Returns:
        Human-readable prompt listing intent, non-private parameters, Returns/Yields when applicable, and Raises when the body raises.
    """
    wanted = ["a brief intent description"]
    parameters = [name for name in signature_param_names(node) if not name.startswith("_")]
    # Ask for parameter descriptions only when the callable accepts non-private arguments beyond self/cls.
    if parameters:
        entries = "an entry for parameter" if len(parameters) == 1 else "entries for parameters"
        wanted.append(f"{entries} {quoted_names(parameters)}")
    # Generators document yielded items; non-generators ask for Returns only when a meaningful value is returned.
    if is_generator(node):
        wanted.append("a Yields section")
    elif _returns_documentable_value(node):
        wanted.append("a Returns section")
    # Ask for Raises only when the function body contains an explicit `raise` statement.
    if has_raise_in_body(node):
        wanted.append("a Raises section")
    listed = wanted[0] if len(wanted) == 1 else f"{', '.join(wanted[:-1])} and {wanted[-1]}"
    return f"Function {symbol!r} needs a docstring with {listed}."


def _returns_documentable_value(node: FunctionNode) -> bool:
    """Decide whether a callable returns a value that callers need documented in a `Returns:` section.

    Args:
        node: Function inspected for a non-None return annotation or an explicit value-bearing return/yield statement.

    Returns:
        True when callers receive a non-None value; False for `-> None` annotations or procedures with no returned value.
    """
    # Trust an explicit return type annotation first so `-> None` procedures never get a noisy Returns prompt.
    if has_return_annotation(node):
        return not has_none_only_return(node)
    return returns_value(node)
