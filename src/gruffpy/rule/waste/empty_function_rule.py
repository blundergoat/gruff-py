"""Flag stubbed-out functions and methods whose body is only `pass`, `...`, or a constant during `gruff-py analyse` and `hook` runs.

Use this rule to catch unfinished AI-generated placeholders and leftover no-op methods before they silently ship.
Intentional interface declarations and test doubles stay quiet so teams only review suspicious empty bodies.

- Exempt declarations: abstract methods, `@typing.overload` stubs, `Protocol`/ABC/pluggy/`TYPE_CHECKING` stubs, and framework-hook decorators.
- Exempt test helpers: empty methods inside test-double classes (`Dummy`, `Fake`, `Mock`, `Spy`, `Stub`) or classes nested inside tests.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import (
    _is_empty_body,
    has_framework_decorator,
    is_abstract_method,
    is_overload_stub,
    is_pluggy_hookspec,
    is_protocol_method_stub,
    is_type_checking_stub,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_TEST_DOUBLE_TOKENS: frozenset[str] = frozenset({"dummy", "fake", "mock", "spy", "stub"})


class EmptyFunctionRule(Rule):
    """Detect functions and methods whose body is only a no-op placeholder (`pass`, `...`, or a constant).

    The analyser runs this rule on every parsed Python file so reviewers catch unfinished stubs before merging.
    Abstract interfaces, typing overloads, framework hook declarations, and test-double stubs are exempted automatically.
    """

    ID = "waste.empty-function"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata for the registry, `list-rules`, and report formatters.

        Returns:
            Definition for the empty-function warning rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Empty function",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Scan one parsed Python file for non-exempt placeholder functions and methods.

        Called by the analysis runner during `analyse`, `summary`, `report`, and `hook` runs once AST parsing succeeds.

        Args:
            unit: Parsed source file to inspect; `unit.tree` is None for non-Python files, syntax errors, or budget-skipped files.
            context: Rule execution context (unused because this rule has no configurable thresholds).

        Returns:
            One finding per qualifying empty callable; an empty list when the AST is absent or every empty body is exempt.
        """
        # Skip non-Python files, syntax errors, and budget-skipped files that have no AST to inspect.
        if unit.tree is None:
            return []
        definition = self.definition()
        return [_empty_function_finding(unit, definition, node, parents) for node, parents in _empty_functions(unit.tree, unit.file.display_path)]


def _empty_functions(
    tree: ast.AST,
    display_path: str,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, list[ast.AST]]]:
    """Walk the module AST and collect non-exempt empty callables together with their enclosing AST chain.

    Args:
        tree: Parsed module AST whose attached parent links supply enclosing classes and test functions.
        display_path: Relative file path used to limit test-double exemptions to recognized test locations.

    Returns:
        Pairs of reportable empty functions and their outermost-to-innermost ancestors; an empty list when none qualify.
    """
    candidates: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, list[ast.AST]]] = []
    # Walk the whole tree so nested helper classes and test-suite methods are checked alongside top-level functions.
    for node in ast.walk(tree):
        # Skip non-callable AST nodes while walking the module.
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        parents = parent_chain(node)
        # Keep only functions with placeholder bodies that fall outside all declaration and test-double exemptions.
        if _should_report_empty_function(node, parents, display_path):
            candidates.append((node, parents))
    return candidates


def _should_report_empty_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: list[ast.AST],
    display_path: str,
) -> bool:
    """Decide whether one callable has an empty placeholder body that should be shown to the developer.

    Args:
        node: Function or method whose body and decorators are checked.
        parents: Outermost-to-innermost ancestors used for protocol, pluggy, TYPE_CHECKING, and test-double exemptions.
        display_path: Relative source path used to confine the test-double exemption to test files.

    Returns:
        True when the body is a no-op placeholder and no declaration or test-double exemption applies; False otherwise.
    """
    # Real implementations with statements beyond pass/ellipsis/docstring need no further checks.
    if not _is_empty_body(node.body):
        return False
    return not (
        is_abstract_method(node)
        or is_overload_stub(node)
        or is_pluggy_hookspec(node, parents)
        or is_type_checking_stub(node, parents)
        or is_protocol_method_stub(node, parents)
        or has_framework_decorator(node)
        or _is_test_double_method(parents, display_path)
    )


def _is_test_double_method(parents: list[ast.AST], display_path: str) -> bool:
    """Exempt no-op methods on test-double classes (`Fake*`, `Stub*`, etc.) or classes nested inside tests.

    Prevents `gruff-py analyse` from nagging developers about intentional no-op stubs written to satisfy an interface in unit tests.

    Args:
        parents: Ancestors from outermost to immediate parent; walked inward-out so nested stubs check their own class name first.
        display_path: Relative source path; production files return False immediately so production classes named `Fake*` still scan.

    Returns:
        True when the method belongs to a recognized test double or test-nested helper class in a test file; False otherwise.
    """
    # Never apply test-double exemptions outside test files so production stubs cannot silently slip through.
    if not _is_test_path(display_path):
        return False
    # Walk from innermost parent outward so a nested stub inside a suite checks its own name before outer containers.
    for index in range(len(parents) - 1, -1, -1):
        parent_class = parents[index]
        # Inspect only the nearest enclosing class definition; stop once we classify it.
        if isinstance(parent_class, ast.ClassDef):
            # A class named like `FakeTransport` or `DummyClock` is an explicit test double.
            if any(token in _TEST_DOUBLE_TOKENS for token in lower_tokens(parent_class.name)):
                return True
            # For example, `class LocalClient:` declared inside `def test_timeout():` or `class TestRetry:` is also an inline test double.
            return any(_is_test_container(ancestor) for ancestor in parents[:index])
    return False


def _is_test_container(node: ast.AST) -> bool:
    """Check whether an ancestor node above a nested helper class is a test function or test suite class.

    Args:
        node: Enclosing AST node sitting outside a nested class inside a test file.

    Returns:
        True for an enclosing function or a test-suite class; False for module nodes or non-test helper classes.
    """
    # Any class declared inside a function/method in a test file is a local fixture or double for that test.
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return True
    # A class nested inside `class TestFoo:` or a `unittest.TestCase` subclass is scoped to that test suite.
    if isinstance(node, ast.ClassDef):
        return _is_test_class(node)
    return False


def _is_test_class(node: ast.ClassDef) -> bool:
    """Check whether a class follows pytest or unittest test-suite conventions by name or `TestCase` base.

    Args:
        node: Class definition evaluated as an enclosing test suite container.

    Returns:
        True when the class starts with `Test`, ends with `Test`/`TestCase`, or inherits from a `*TestCase` base; False otherwise.
    """
    # Recognize standard pytest (`Test*`) and unittest (`*Test`, `*TestCase`) suite names directly.
    if node.name.startswith("Test") or node.name.endswith(("Test", "TestCase")):
        return True
    return any(_base_leaf_name(base).endswith("TestCase") for base in node.bases)


def _base_leaf_name(base: ast.expr) -> str:
    """Extract the trailing class identifier from a bare (`TestCase`) or dotted (`unittest.TestCase`) base expression.

    Args:
        base: Base-class AST expression from a class definition's `bases` list.

    Returns:
        Trailing identifier string, or an empty string for complex expressions such as calls or subscripts.
    """
    # Simple imported base such as `class Suite(TestCase):`.
    if isinstance(base, ast.Name):
        return base.id
    # Module-qualified base such as `class Suite(unittest.TestCase):`.
    if isinstance(base, ast.Attribute):
        return base.attr
    return ""


def _is_test_path(display_path: str) -> bool:
    """Recognize test locations for the empty-function test-double exemption.

    Args:
        display_path: Display path whose separators are normalized before checking directory segments and the filename.

    Returns:
        True for a path starting with tests/, containing /tests/, or having a filename starting with test_; checks are case-sensitive.
    """
    normalised = display_path.replace("\\", "/")
    filename = normalised.rsplit("/", 1)[-1]
    return normalised.startswith("tests/") or "/tests/" in normalised or filename.startswith("test_")


def _empty_function_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: list[ast.AST],
) -> Finding:
    """Build a finding for one reportable placeholder function.

    Args:
        unit: Source unit supplying the finding display path.
        definition: Rule metadata supplying the finding identity, classification and confidence.
        node: Reportable function whose declaration line and end line locate the finding.
        parents: Enclosing nodes used with the function name to build its qualified symbol.

    Returns:
        Finding for the function source span, carrying its qualified symbol and the supplied rule metadata.
    """
    symbol = qualified_symbol(node, parents)
    return Finding(
        rule_id=definition.id,
        message=f"Function {symbol!r} has an empty body.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Implement the function, delete it, or mark it as abstract/overload."),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )
