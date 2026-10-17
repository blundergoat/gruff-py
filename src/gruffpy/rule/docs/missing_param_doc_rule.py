"""``docs.missing-param-doc`` - documented function with an undocumented parameter.

Fires once per documented public function whose docstring has no matching
``@param`` / ``Args:`` / ``Parameters`` entry for one or more signature
parameters, and names every such parameter. Skips ``self`` / ``cls``,
``_``-prefixed params, dunder methods, and functions without docstrings.

The ``everyCallable`` option, off by default, brings underscore-private
functions and methods into scope and stops an entry with no description from
counting as documentation.
"""

import ast
from dataclasses import dataclass

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import is_overload_stub
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import DocstringField, DocstringStyle, extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    EVERY_CALLABLE_OPTION,
    every_callable_enabled,
    is_in_documentation_scope,
    is_property_setter_or_deleter,
    quoted_names,
    signature_param_names,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _ParamDocCandidate:
    """Function whose docstring is missing one or more parameter entries."""

    node: FunctionNode
    symbol: str
    missing: list[str]
    style: DocstringStyle


class MissingParamDocRule(Rule):
    """Detect documented functions with missing parameter documentation."""

    ID = "docs.missing-param-doc"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the missing parameter documentation rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Missing parameter documentation",
            description=(
                "Flags a public function whose docstring has no entry for one or more parameters, naming each one; "
                "with `everyCallable`, also underscore-private functions and methods, and an entry with no "
                "description does not count."
            ),
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={EVERY_CALLABLE_OPTION: False},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented function parameters.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer; its
                ``everyCallable`` option widens the rule.

        Returns:
            One finding per documented function in scope that misses parameter entries.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        every_callable = every_callable_enabled(context, definition)
        return [_missing_param_finding(unit, definition, candidate) for candidate in _param_doc_candidates(unit.tree, every_callable=every_callable)]


def _param_doc_candidates(tree: ast.AST, *, every_callable: bool) -> list[_ParamDocCandidate]:
    candidates: list[_ParamDocCandidate] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        candidate = _param_doc_candidate(node, every_callable=every_callable)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _param_doc_candidate(node: FunctionNode, *, every_callable: bool) -> _ParamDocCandidate | None:
    if _should_skip_param_doc_check(node, every_callable=every_callable):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None:
        return None

    documented = {param.name for param in parsed.params if param.name and (not every_callable or _has_description(param))}
    parameters = [param for param in signature_param_names(node) if not param.startswith("_")]
    missing = [param for param in parameters if param not in documented]
    if not missing:
        return None
    return _ParamDocCandidate(
        node=node,
        symbol=qualified_symbol(node, parent_chain(node)),
        missing=missing,
        style=parsed.style,
    )


def _should_skip_param_doc_check(node: FunctionNode, *, every_callable: bool) -> bool:
    return not is_in_documentation_scope(node.name, every_callable=every_callable) or is_overload_stub(node) or is_property_setter_or_deleter(node)


def _has_description(field: DocstringField) -> bool:
    """Return whether a docstring entry says something about its parameter."""
    return bool(field.description and field.description.strip())


def _missing_param_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _ParamDocCandidate,
) -> Finding:
    entries = "a docstring entry describing parameter" if len(candidate.missing) == 1 else "docstring entries describing parameters"
    return Finding(
        rule_id=definition.id,
        message=f"Function {candidate.symbol!r} needs {entries} {quoted_names(candidate.missing)}.",
        file_path=unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.node.end_lineno,
        symbol=candidate.symbol,
        remediation=(
            "Document each named parameter's purpose "
            "(Google ``Args:``, NumPy ``Parameters``, or Sphinx ``:param:``). "
            "Name what it is for, not just its type."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"parameters": candidate.missing, "style": candidate.style.value},
    )
