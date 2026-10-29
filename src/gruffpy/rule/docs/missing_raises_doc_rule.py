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
    """Collect each function definition in the tree that this rule flags, paired with its detected docstring style.

    The tree is searched with ast.walk, so nested functions and methods are judged individually alongside top-level ones;
    ``_missing_raises_doc_style`` decides whether each one is flagged.

    Args:
        tree: Parsed module tree to search for function and async function definitions at any depth.
        every_callable: Whether the rule's ``everyCallable`` option is on, bringing underscore-private names into scope.

    Returns:
        Pairs of flagged function definition and its docstring style, in ast.walk order; an empty list when no function is flagged.
    """
    candidates: list[tuple[FunctionNode, DocstringStyle]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        style = _missing_raises_doc_style(node, every_callable=every_callable)
        if style is not None:
            candidates.append((node, style))
    return candidates


def _missing_raises_doc_style(node: FunctionNode, *, every_callable: bool) -> DocstringStyle | None:
    """Return the docstring style of a function this rule flags, or None when the function is not flagged.

    A function is flagged when ``_should_skip_raises_doc_check`` does not skip it and its docstring parses with no raises entries.

    Args:
        node: Function or async function definition to judge.
        every_callable: Whether the rule's ``everyCallable`` option is on, bringing underscore-private names into scope.

    Returns:
        The parsed docstring's detected style for a flagged function; None when ``_should_skip_raises_doc_check`` skips the function, it has no
        docstring, its docstring is empty, whitespace-only or fails to parse, or its docstring already lists raises entries.
    """
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
    """Decide whether a function falls outside this rule before its docstring is read.

    Args:
        node: Function or async function definition to test.
        every_callable: Whether the rule's ``everyCallable`` option is on, bringing underscore-private names into scope.

    Returns:
        True when ``is_in_documentation_scope`` rejects the name, the function is an overload stub, it is a property setter or deleter, or
        ``has_raise_in_body`` finds no raise statement outside nested functions and lambdas; False when the rule should go on to read the docstring.
    """
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
    """Build the finding reported for a function this rule flags.

    The finding spans the function from its def line to its last line, names it by the qualified symbol built from its parent chain, and takes its
    rule ID, default severity, pillar, tier, confidence and secondary pillars from the rule definition.

    Args:
        unit: Analysis unit whose display path becomes the finding's file path.
        definition: This rule's definition, supplying the rule ID, default severity, pillar, tier, confidence and secondary pillars.
        node: Flagged function definition that sets the finding's line span and symbol.
        style: Detected docstring style, whose value is recorded under the finding's ``style`` metadata key.

    Returns:
        Finding whose message names the function's qualified symbol and whose fixed remediation asks for a section naming each exception type and the
        condition that triggers it.
    """
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
