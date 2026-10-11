"""``docs.missing-return-doc`` - non-None return type but no Returns section.

Fires on documented public functions whose declared return type is not ``None``
and whose docstring lacks a Returns / :returns: entry. Skips functions that
declare ``-> None`` (or no return annotation at all) and ``__init__`` constructors.

The ``everyCallable`` option, off by default, brings underscore-private
functions and methods into scope, and also functions with no return
annotation whose own body returns or yields a value.
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
    has_none_only_return,
    has_return_annotation,
    is_in_documentation_scope,
    is_property_setter_or_deleter,
    returns_value,
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
            description=(
                "Flags a public function annotated to return a value whose docstring has no Returns section; with "
                "`everyCallable`, also underscore-private functions and methods, and an unannotated function whose "
                "body returns or yields a value."
            ),
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={EVERY_CALLABLE_OPTION: False},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented return values.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer; its
                ``everyCallable`` option widens the rule.

        Returns:
            Findings for documented functions in scope missing Returns sections.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        every_callable = every_callable_enabled(context, definition)
        return [
            _missing_return_doc_finding(unit, definition, node, style)
            for node, style in _missing_return_doc_nodes(unit.tree, every_callable=every_callable)
        ]


def _missing_return_doc_nodes(tree: ast.AST, *, every_callable: bool) -> list[tuple[FunctionNode, DocstringStyle]]:
    candidates: list[tuple[FunctionNode, DocstringStyle]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        style = _missing_return_doc_style(node, every_callable=every_callable)
        if style is not None:
            candidates.append((node, style))
    return candidates


def _missing_return_doc_style(node: FunctionNode, *, every_callable: bool) -> DocstringStyle | None:
    if _should_skip_return_doc_check(node, every_callable=every_callable):
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


def _should_skip_return_doc_check(node: FunctionNode, *, every_callable: bool) -> bool:
    if (
        not is_in_documentation_scope(node.name, every_callable=every_callable)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
        or has_none_only_return(node)
    ):
        return True
    if has_return_annotation(node):
        return False
    # Without an annotation, only the widened scope reads the body to see whether a value comes back.
    return not (every_callable and returns_value(node))


def _missing_return_doc_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: FunctionNode,
    style: DocstringStyle,
) -> Finding:
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=(f"Function {symbol!r} returns a non-None value and needs a Returns section in its docstring."),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=(
            "Add a Returns / :returns: section describing the value's shape and meaning, especially the edge cases (None, empty, sentinel values)."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"style": style.value},
    )
