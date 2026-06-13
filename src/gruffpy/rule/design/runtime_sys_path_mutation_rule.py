"""``design.runtime-sys-path-mutation`` - sys.path mutated outside script entry points.

Flags ``sys.path.insert(...)`` and ``sys.path.append(...)`` executed at import
time or inside library functions - anywhere outside an
``if __name__ == "__main__":`` block, a file under a ``tests`` directory, or a
``conftest.py``.

``insert(0, ...)`` is the riskier shape: it shadows every later top-level
import for the whole process, so one colliding filename in the inserted
directory breaks the host application. The distinction is carried in the
finding message and ``metadata.method`` / ``metadata.argumentPosition``; the
rule itself ships at a single advisory severity per the single-severity
contract.
"""

import ast
from pathlib import PurePosixPath

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
_REMEDIATION = (
    "Package the code so imports resolve without process-wide path surgery: "
    "an editable install (pip install -e), a src layout, or PYTHONPATH in the "
    "runner configuration. Keep any unavoidable sys.path mutation inside the "
    '`if __name__ == "__main__":` block of the script that needs it.'
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
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            method = _sys_path_mutation_method(node)
            if method is None or _is_inside_main_block(node):
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
    if not (
        isinstance(receiver, ast.Attribute)
        and receiver.attr == "path"
        and isinstance(receiver.value, ast.Name)
        and receiver.value.id == "sys"
    ):
        return None
    return callee.attr


def _is_inside_main_block(node: ast.AST) -> bool:
    current: ast.AST | None = getattr(node, "parent", None)
    while current is not None:
        if isinstance(current, ast.If) and _is_main_guard(current.test):
            return True
        current = getattr(current, "parent", None)
    return False


def _is_main_guard(test: ast.expr) -> bool:
    if not (isinstance(test, ast.Compare) and len(test.ops) == 1):
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    operands = [test.left, *test.comparators]
    has_dunder_name = any(
        isinstance(operand, ast.Name) and operand.id == "__name__" for operand in operands
    )
    has_main_literal = any(
        isinstance(operand, ast.Constant) and operand.value == "__main__" for operand in operands
    )
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
