"""``docs.missing-function-docstring`` - public function/method without a docstring.

Public = the name does not start with ``_``. Dunder methods, abstract methods,
pytest-style ``test_*`` functions in test files, ``@typing.overload`` stubs,
and ``@<name>.setter``/``@<name>.deleter`` methods are exempt. ``@property``
getters require a docstring like any public method.
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
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
    is_test_file,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class MissingFunctionDocstringRule(Rule):
    """Detect public functions and methods that lack documentation."""

    ID = "docs.missing-function-docstring"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the missing function docstring rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing function docstring",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented public functions.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer.

        Returns:
            Findings for public functions or methods missing docstrings.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _missing_function_docstring_finding(unit, definition, node, parents)
            for node, parents in _undocumented_functions(unit)
        ]


def _undocumented_functions(unit: AnalysisUnit) -> list[tuple[FunctionNode, list[ast.AST]]]:
    assert unit.tree is not None
    candidates: list[tuple[FunctionNode, list[ast.AST]]] = []
    for node in ast.walk(unit.tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        parents = parent_chain(node)
        if _should_report_missing_function_docstring(node, parents, unit.file.display_path):
            candidates.append((node, parents))
    return candidates


def _should_report_missing_function_docstring(
    node: FunctionNode,
    parents: list[ast.AST],
    display_path: str,
) -> bool:
    if not is_public(node.name) or is_dunder(node.name):
        return False
    if node.name.startswith("test_") and is_test_file(display_path):
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
    # Nested function whose name is referenced at most once inside the
    # enclosing function is treated as a closure / one-shot callback (regex
    # sub callbacks, SSE `event_generator`, mock-class method stubs). Forcing
    # a docstring on these is noise - the call-site context already documents
    # intent.
    enclosing = next(
        (p for p in reversed(parents) if isinstance(p, ast.FunctionDef | ast.AsyncFunctionDef)),
        None,
    )
    if enclosing is None:
        return False
    return _name_reference_count_excluding(enclosing, node.name, node) <= 1


def _name_reference_count_excluding(root: ast.AST, name: str, exclude: ast.AST) -> int:
    count = 0
    stack: list[ast.AST] = list(ast.iter_child_nodes(root))
    while stack:
        current = stack.pop()
        if current is exclude:
            # Don't descend into the closure's own body - recursive references
            # inside the closure shouldn't count toward "external callsites".
            continue
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
    symbol = qualified_symbol(node, parents)
    return Finding(
        rule_id=definition.id,
        message=f"Function {symbol!r} needs a brief intent description in its docstring.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
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
