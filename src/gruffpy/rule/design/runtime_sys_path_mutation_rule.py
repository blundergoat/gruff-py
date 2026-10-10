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

        Advisory severity per the new-rule rollout policy and the
        single-severity contract; the insert(0)-shadows-the-process risk is
        carried in the message and metadata rather than a severity tier.
        High confidence because the matched receiver is the literal
        ``sys.path`` attribute chain and the exemptions are structural.

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
        """Flag sys.path mutations executed at import time or in library code.

        Skips files under a ``tests`` directory and ``conftest.py`` entirely,
        and calls lexically inside an ``if __name__ == "__main__":`` block.
        In a standalone script a top-level call is skipped as well, but not
        one inside a function or in a guard's ``else`` branch.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per mutating call outside the exempt locations.
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
            # The guard body runs only as a script; a script's top level runs in its own process too.
            if branch == "body" or (is_script and branch is None and _is_module_level(node)):
                continue
            findings.append(_build_finding(definition, unit, node, method))
        return findings


def _is_exempt_file(display_path: str) -> bool:
    path = PurePosixPath(display_path.replace("\\", "/"))
    if path.name == "conftest.py":
        return True
    return "tests" in path.parts[:-1]


def _sys_path_mutation_method(node: ast.Call) -> str | None:
    callee = node.func
    if not (isinstance(callee, ast.Attribute) and callee.attr in _MUTATING_METHODS):
        return None
    receiver = callee.value
    if not (isinstance(receiver, ast.Attribute) and receiver.attr == "path" and isinstance(receiver.value, ast.Name) and receiver.value.id == "sys"):
        return None
    return callee.attr


def _is_standalone_script(unit: AnalysisUnit, tree: ast.AST) -> bool:
    """Return whether a file is run as its own process rather than imported by another module.

    Args:
        unit: Source file whose path and first line are read.
        tree: The file's parsed syntax tree.

    Returns:
        True for a file that opens with a shebang, sits under a ``scripts``, ``bin`` or ``tools`` directory, or
        carries an ``if __name__ == "__main__":`` guard anywhere.
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
    # A compound entry-point guard (``__name__ == "__main__" and ...``) still
    # only runs in the script entry point, so it is exempt too.
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
