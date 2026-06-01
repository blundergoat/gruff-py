"""Function/method whose body is ``pass`` or ``...`` only.

Skipped for: abstract methods, ``@typing.overload`` stubs, methods in
Protocol/ABC subclasses, and functions carrying framework-hook decorators.
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
    is_protocol_method_stub,
)
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.naming._identifier_tokenizer import lower_tokens
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

_TEST_DOUBLE_TOKENS: frozenset[str] = frozenset({"dummy", "fake", "mock", "spy", "stub"})


class EmptyFunctionRule(Rule):
    """Detect functions whose body is only `pass` or `...` outside of abstract or overload stubs."""

    ID = "waste.empty-function"

    def definition(self) -> RuleDefinition:
        """Describe the empty-function rule as a high-confidence dead-code warning.

        High confidence because ``pass``/``...``-only bodies are structurally
        unambiguous; the rule defers to ``is_abstract_method``,
        ``is_overload_stub``, Protocol-stub detection, and framework
        decorators to suppress the legitimate cases.

        Returns:
            Definition for the empty-function rule under the dead-code pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Empty function",
            pillar=Pillar.DEAD_CODE,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag functions and methods whose body is just ``pass`` or ``...``.

        Skips abstract methods, ``@typing.overload`` stubs, Protocol stubs,
        and framework-hook decorators - these legitimately have empty bodies.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per non-exempt empty function definition.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _empty_function_finding(unit, definition, node, parents)
            for node, parents in _empty_functions(unit.tree, unit.file.display_path)
        ]


def _empty_functions(
    tree: ast.AST,
    display_path: str,
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, list[ast.AST]]]:
    candidates: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, list[ast.AST]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        parents = parent_chain(node)
        if _should_report_empty_function(node, parents, display_path):
            candidates.append((node, parents))
    return candidates


def _should_report_empty_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: list[ast.AST],
    display_path: str,
) -> bool:
    if not _is_empty_body(node.body):
        return False
    return not (
        is_abstract_method(node)
        or is_overload_stub(node)
        or is_protocol_method_stub(node, parents)
        or has_framework_decorator(node)
        or _is_test_double_method(parents, display_path)
    )


def _is_test_double_method(parents: list[ast.AST], display_path: str) -> bool:
    if not _is_test_path(display_path):
        return False
    # parents runs outermost -> immediate, so reverse to take the innermost enclosing
    # class: a nested stub (``class Outer: class _FakeClient: ...``) is named by the
    # inner class, not the outer suite, so the outermost match misses the exemption.
    parent_class = next(
        (parent for parent in reversed(parents) if isinstance(parent, ast.ClassDef)), None
    )
    if parent_class is None:
        return False
    return any(token in _TEST_DOUBLE_TOKENS for token in lower_tokens(parent_class.name))


def _is_test_path(display_path: str) -> bool:
    normalised = display_path.replace("\\", "/")
    filename = normalised.rsplit("/", 1)[-1]
    return (
        normalised.startswith("tests/") or "/tests/" in normalised or filename.startswith("test_")
    )


def _empty_function_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parents: list[ast.AST],
) -> Finding:
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
