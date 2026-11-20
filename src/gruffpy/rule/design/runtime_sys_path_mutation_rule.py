"""``design.runtime-sys-path-mutation`` - sys.path mutated outside script entry points.

Flags ``sys.path.insert(...)`` and ``sys.path.append(...)`` executed at import
time or inside library functions. A standalone script - a file that carries an
``if __name__ == "__main__":`` guard, opens with a shebang, or sits under a
``scripts``, ``bin`` or ``tools`` directory - may change the path at its top
level, where the insert has to run before the sibling imports that need it.
Inside a function the call still reports: flask's ``cli.py`` carries a guard
and is imported by ``flask`` itself, so a caller inherits the mutation. A call
inside a guard's ``else`` branch runs only when the file is imported, so it
still reports too. Files under a ``tests`` directory and ``conftest.py`` are
exempt.

``insert(0, ...)`` is the riskier shape: it shadows every later top-level
import for the whole process, so one colliding filename in the inserted
directory breaks the host application. The distinction is carried in the
finding message and ``metadata.method`` / ``metadata.argumentPosition``; the
rule itself ships at a single advisory severity per the single-severity
contract.
"""

import ast
from pathlib import PurePosixPath
from typing import Literal

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_MUTATING_METHODS: frozenset[str] = frozenset({"insert", "append"})
# Conventional homes for files that are run, never imported.
_SCRIPT_DIRECTORIES: frozenset[str] = frozenset({"scripts", "bin", "tools"})
_REMEDIATION = (
    "Package the code so imports resolve without process-wide path surgery: "
    "an editable install (pip install -e), a src layout, or PYTHONPATH in the "
    "runner configuration. A standalone script may change sys.path at its top "
    'level once it is recognisable as one: an `if __name__ == "__main__":` '
    "guard, a shebang, or a home under scripts/, bin/ or tools/."
)


class RuntimeSysPathMutationRule(Rule):
    """Detect sys.path.insert/append outside __main__ blocks, tests, and conftest."""

    ID = "design.runtime-sys-path-mutation"

    def definition(self) -> RuleDefinition:
        """Describe the runtime-sys-path-mutation rule as a high-confidence advisory.

        Advisory severity follows the rollout and single-severity policies; insert(0) risk is carried in the message and metadata.
        Confidence is high because matching requires the literal sys.path receiver and uses structural exemptions.

        Returns:
            Definition for the runtime-sys-path-mutation rule under the
            design pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Runtime sys.path mutation",
            pillar=Pillar.DESIGN,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag sys.path.insert and sys.path.append calls outside the rule's script and test exemptions.

        Files under tests directories and conftest.py files are exempt. The nearest main guard exempts calls in its body only.
        Outside any main guard, recognised scripts exempt calls with no enclosing function or lambda, including calls in class bodies.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            Findings for mutating calls outside exempt locations; empty when no parsed tree, no sys.path text or no reportable call is present.
        """
        if unit.tree is None or "sys.path" not in unit.source:
            return []
        if _is_exempt_file(unit.file.display_path):
            return []
        is_script = _is_standalone_script(unit, unit.tree)
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            method = _sys_path_mutation_method(node)
            if method is None:
                continue
            branch = _main_guard_branch(node)
            # A call in the nearest guard's test or else branch remains reportable even inside an outer main guard's body.
            if branch == "body" or (is_script and branch is None and _is_module_level(node)):
                continue
            findings.append(_build_finding(definition, unit, node, method))
        return findings


def _is_exempt_file(display_path: str) -> bool:
    """Decide whether a file is exempt from the rule because it is a conftest.py or sits under a tests directory.

    Args:
        display_path: Display path of the analysed file; backslashes are treated as path separators before the path is split.

    Returns:
        True when the file name is conftest.py or any directory component is exactly tests; False otherwise, so the file is analysed.
    """
    path = PurePosixPath(display_path.replace("\\", "/"))
    if path.name == "conftest.py":
        return True
    return "tests" in path.parts[:-1]


def _sys_path_mutation_method(node: ast.Call) -> str | None:
    """Return insert or append when a call's callee is written as sys.path.insert or sys.path.append.

    The receiver must be path on the bare name sys. Calls through an alias such as system.path or through a directly imported path are ignored.

    Args:
        node: Call node to inspect.

    Returns:
        The method name, insert or append, which the caller records in the finding message and metadata; None when the callee is any other expression.
    """
    callee = node.func
    if not (isinstance(callee, ast.Attribute) and callee.attr in _MUTATING_METHODS):
        return None
    receiver = callee.value
    if not (isinstance(receiver, ast.Attribute) and receiver.attr == "path" and isinstance(receiver.value, ast.Name) and receiver.value.id == "sys"):
        return None
    return callee.attr


def _is_standalone_script(unit: AnalysisUnit, tree: ast.AST) -> bool:
    """Identify files treated as standalone scripts when deciding which sys.path mutations to exempt.

    Args:
        unit: Source file whose path and first line are read.
        tree: The file's parsed syntax tree.

    Returns:
        True for a shebang, a scripts, bin or tools directory component, or any recognized main guard; False otherwise.
    """
    if unit.source.startswith("#!"):
        return True
    directories = PurePosixPath(unit.file.display_path.replace("\\", "/")).parts[:-1]
    if not _SCRIPT_DIRECTORIES.isdisjoint(directories):
        return True
    return any(isinstance(node, ast.If) and _is_main_guard(node.test) for node in ast.walk(tree))


def _is_module_level(node: ast.AST) -> bool:
    """Return whether a node runs when its module executes, rather than when a function is called.

    Args:
        node: AST node with parent links.

    Returns:
        False when a function or lambda encloses the node; a caller of that function may be another module.
    """
    current: ast.AST | None = getattr(node, "parent", None)
    # Any enclosing function defers the call to whoever invokes it.
    while current is not None:
        if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            return False
        current = getattr(current, "parent", None)
    return True


def _main_guard_branch(node: ast.AST) -> Literal["body", "else"] | None:
    """Return which branch of an enclosing ``if __name__ == "__main__":`` guard holds a node.

    Args:
        node: AST node with parent links.

    Returns:
        ``"body"`` inside the guard, which runs only as a script; ``"else"`` inside its ``else`` or ``elif``
        branch, which runs when the module is imported; ``None`` outside every guard.
    """
    child: ast.AST = node
    current: ast.AST | None = getattr(node, "parent", None)
    # The nearest enclosing guard decides, so climb until one is found.
    while current is not None:
        if isinstance(current, ast.If) and _is_main_guard(current.test):
            return "body" if child in current.body else "else"
        child = current
        current = getattr(current, "parent", None)
    return None


def _is_main_guard(test: ast.expr) -> bool:
    """Recognize an equality comparison between the bare name __name__ and the string __main__ in either operand order.

    An and expression matches if any operand is itself a main guard. An or expression, inequality or chained comparison does not match.

    Args:
        test: Condition expression to examine, normally the test of an if statement.

    Returns:
        True when the condition is a main guard, which callers use to recognise a standalone script and the guard branch that holds a call; False
        otherwise.
    """
    # An and condition with a main check can exempt a call when this is its nearest main guard and the call is in its body.
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return any(_is_main_guard(value) for value in test.values)
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    operands = [test.left, *test.comparators]
    has_dunder_name = any(isinstance(operand, ast.Name) and operand.id == "__name__" for operand in operands)
    has_main_literal = any(isinstance(operand, ast.Constant) and operand.value == "__main__" for operand in operands)
    return has_dunder_name and has_main_literal


def _argument_position(call: ast.Call, method: str) -> int | None:
    """Read the index passed as the first positional argument of a sys.path insert call.

    Args:
        call: Mutating call node whose positional arguments are read.
        method: Method name returned by _sys_path_mutation_method; only insert carries a position.

    Returns:
        The first positional argument's value when it is an integer or boolean constant in an insert call.
        None for append, a missing positional argument, or any other expression, including a negative literal such as -1.
    """
    if method != "insert" or not call.args:
        return None
    first = call.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, int):
        return first.value
    return None


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    call: ast.Call,
    method: str,
) -> Finding:
    """Build the finding for one sys.path mutation call, choosing its message from the method and insert index.

    An insert index equal to 0, including False, gets the shadowing message. Other calls get the execution-order message naming their method.
    Metadata always records method and adds argumentPosition when an insert's first argument is an integer or boolean constant.

    Args:
        definition: Rule definition supplying the rule id, severity, pillar, tier, confidence and secondary pillars.
        unit: Analysed file whose display path becomes the finding's file path.
        call: The mutating call node; its start and end lines locate the finding.
        method: insert or append, as returned by _sys_path_mutation_method.

    Returns:
        The finding located at the call's line span, carrying the shared packaging remediation text and the method and argumentPosition metadata
        described above.
    """
    position = _argument_position(call, method)
    if method == "insert" and position == 0:
        message = (
            "`sys.path.insert(0, ...)` at runtime shadows every later top-level "
            "import for the whole process; one colliding filename in that "
            "directory breaks the host application. Imports need packaging, "
            "not path surgery."
        )
    else:
        message = (
            f"`sys.path.{method}(...)` at runtime makes imports depend on "
            "execution order; the import layout needs packaging (editable "
            "install or src layout) instead."
        )
    metadata: dict[str, object] = {"method": method}
    if position is not None:
        metadata["argumentPosition"] = position
    return Finding(
        rule_id=definition.id,
        message=message,
        file_path=unit.file.display_path,
        line=getattr(call, "lineno", 1),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(call, "end_lineno", None),
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata=metadata,
    )
