"""``docs.missing-raises-doc`` - documented function that raises but lacks a Raises section.

Public functions only. Walks the body for ``raise`` statements, stopping at
nested function/lambda boundaries (those raises belong to the nested scope).
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
    has_raise_in_body,
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
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
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.LOW,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented raise behavior.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer.

        Returns:
            Findings for documented public functions that raise without docs.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _missing_raises_doc_finding(unit, definition, node, style)
            for node, style in _missing_raises_doc_nodes(unit.tree)
        ]


def _missing_raises_doc_nodes(tree: ast.AST) -> list[tuple[FunctionNode, DocstringStyle]]:
    candidates: list[tuple[FunctionNode, DocstringStyle]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        style = _missing_raises_doc_style(node)
        if style is not None:
            candidates.append((node, style))
    return candidates


def _missing_raises_doc_style(node: FunctionNode) -> DocstringStyle | None:
    if _should_skip_raises_doc_check(node):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None or parsed.raises:
        return None
    return parsed.style


def _should_skip_raises_doc_check(node: FunctionNode) -> bool:
    return (
        not is_public(node.name)
        or is_dunder(node.name)
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
        message=(
            f"Function {symbol!r} raises exceptions and needs a Raises section in its docstring."
        ),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=(
            "Add a Raises / :raises: section naming each exception type "
            "and the condition that triggers it."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"style": style.value},
    )
