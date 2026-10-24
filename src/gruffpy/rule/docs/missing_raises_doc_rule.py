"""``docs.missing-raises-doc`` - documented function that raises but lacks a Raises section.

Public functions only, unless the ``everyCallable`` option, off by default,
brings underscore-private functions and methods into scope. Walks the body for
``raise`` statements, stopping at nested function/lambda boundaries (those
raises belong to the nested scope).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import is_overload_stub
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import DocstringStyle, extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    EVERY_CALLABLE_OPTION,
    every_callable_enabled,
    has_raise_in_body,
    is_in_documentation_scope,
    is_property_setter_or_deleter,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class MissingRaisesDocRule(Rule):
    """Detect documented functions that raise without a Raises section."""

    ID = "docs.missing-raises-doc"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the missing raises documentation rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing raises documentation",
            description=(
                "Flags a public function whose body raises an exception and whose docstring has no Raises section; "
                "with `everyCallable`, also underscore-private functions and methods."
            ),
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
            default_options={EVERY_CALLABLE_OPTION: False},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented raise behavior.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer; its
                ``everyCallable`` option widens the rule.

        Returns:
            Findings for documented functions in scope that raise without docs.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        every_callable = every_callable_enabled(context, definition)
        return [
            _missing_raises_doc_finding(unit, definition, node, style)
            for node, style in _missing_raises_doc_nodes(unit.tree, every_callable=every_callable)
        ]


def _missing_raises_doc_nodes(tree: ast.AST, *, every_callable: bool) -> list[tuple[FunctionNode, DocstringStyle]]:
    candidates: list[tuple[FunctionNode, DocstringStyle]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        style = _missing_raises_doc_style(node, every_callable=every_callable)
        if style is not None:
            candidates.append((node, style))
    return candidates


def _missing_raises_doc_style(node: FunctionNode, *, every_callable: bool) -> DocstringStyle | None:
    if _should_skip_raises_doc_check(node, every_callable=every_callable):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None or parsed.raises:
        return None
    return parsed.style


def _should_skip_raises_doc_check(node: FunctionNode, *, every_callable: bool) -> bool:
    return (
        not is_in_documentation_scope(node.name, every_callable=every_callable)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
        or not has_raise_in_body(node)
    )


def _missing_raises_doc_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: FunctionNode,
    style: DocstringStyle,
) -> Finding:
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(f"Function {symbol!r} raises exceptions and needs a Raises section in its docstring."),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Add a Raises / :raises: section naming each exception type and the condition that triggers it."),
        secondary_pillars=definition.secondary_pillars,
        metadata={"style": style.value},
    )
