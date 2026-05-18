"""``docs.missing-return-doc`` — non-None return type but no Returns section.

Fires on documented public functions whose declared return type is not ``None``
and whose docstring lacks a Returns / :returns: entry. Skips functions that
declare ``-> None`` (or no return annotation at all) and ``__init__`` constructors.
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
    has_none_only_return,
    has_return_annotation,
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


class MissingReturnDocRule(Rule):
    """Detect documented functions whose non-None return value is undocumented."""

    ID = "docs.missing-return-doc"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the missing return documentation rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing return documentation",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented return values.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer.

        Returns:
            Findings for documented public functions missing Returns sections.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _missing_return_doc_finding(unit, definition, node, style)
            for node, style in _missing_return_doc_nodes(unit.tree)
        ]


def _missing_return_doc_nodes(tree: ast.AST) -> list[tuple[FunctionNode, DocstringStyle]]:
    candidates: list[tuple[FunctionNode, DocstringStyle]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        style = _missing_return_doc_style(node)
        if style is not None:
            candidates.append((node, style))
    return candidates


def _missing_return_doc_style(node: FunctionNode) -> DocstringStyle | None:
    if _should_skip_return_doc_check(node):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None:
        return None
    if parsed.returns is not None and (parsed.returns.description or parsed.returns.type_hint):
        return None
    return parsed.style


def _should_skip_return_doc_check(node: FunctionNode) -> bool:
    return (
        not is_public(node.name)
        or is_dunder(node.name)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
        or not has_return_annotation(node)
        or has_none_only_return(node)
    )


def _missing_return_doc_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: FunctionNode,
    style: DocstringStyle,
) -> Finding:
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(f"Function {symbol!r} has a non-None return type but no Returns section."),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Add a Returns / :returns: section describing the value's shape and meaning."),
        secondary_pillars=definition.secondary_pillars,
        metadata={"style": style.value},
    )
