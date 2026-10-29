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
    """Walk the tree and collect the candidate _param_doc_candidate builds for each function or async function definition.

    The walk uses ast.walk, so nested functions and methods are checked too, and candidates come back in that walk order.

    Args:
        tree: Parsed module tree to walk.
        every_callable: Whether the ``everyCallable`` option is on; passed to _param_doc_candidate for each function.

    Returns:
        One candidate per function that _param_doc_candidate reports as missing parameter entries; empty when it reports none.
    """
    candidates: list[_ParamDocCandidate] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        candidate = _param_doc_candidate(node, every_callable=every_callable)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _param_doc_candidate(node: FunctionNode, *, every_callable: bool) -> _ParamDocCandidate | None:
    """Build a candidate for one function when its docstring has no entry for one or more of its signature parameters.

    The function is skipped when _should_skip_param_doc_check excludes it, when it has no docstring, or when parse_docstring returns None. Signature
    parameters come from signature_param_names, and a parameter whose name starts with an underscore is never required. With every_callable on, a
    docstring entry counts only when _has_description finds description text in it.

    Args:
        node: Function definition to check.
        every_callable: Whether the ``everyCallable`` option is on; it brings underscore-private function names into scope and stops an entry without
            a description from counting.

    Returns:
        Candidate holding the node, its qualified symbol, the missing parameter names in the order signature_param_names lists them, and the detected
        docstring style; None when the function is skipped, has no parseable docstring, or has an entry for every required parameter.
    """
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
    """Report whether a function is out of name scope, an overload stub, or a property setter or deleter.

    Name scope comes from is_in_documentation_scope, which leaves dunder names out and admits underscore-private names only when every_callable is on.

    Args:
        node: Function definition to test.
        every_callable: Whether the ``everyCallable`` option is on; it brings underscore-private function names into scope.

    Returns:
        True when the rule must not check the function's parameter entries.
    """
    return not is_in_documentation_scope(node.name, every_callable=every_callable) or is_overload_stub(node) or is_property_setter_or_deleter(node)


def _has_description(field: DocstringField) -> bool:
    """Return whether a docstring entry says something about its parameter.

    Args:
        field: Parameter entry parsed from the docstring.

    Returns:
        True when the entry's description contains non-whitespace text; False when the description is missing or blank.
    """
    return bool(field.description and field.description.strip())


def _missing_param_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _ParamDocCandidate,
) -> Finding:
    """Build the finding that names every missing parameter of one candidate function.

    The message asks for a docstring entry describing parameter when one name is missing, or docstring entries describing parameters when several are,
    followed by the names joined with quoted_names. The metadata records the missing names under parameters and the docstring style value under style.

    Args:
        unit: Analysed file whose display path locates the finding.
        definition: Rule metadata that supplies the rule ID, default severity, pillar, tier, confidence and secondary pillars.
        candidate: Function with missing parameter entries, carrying its node, qualified symbol, missing names and docstring style.

    Returns:
        Finding spanning the function from its def line to its last line, with the candidate's symbol, a fixed remediation and the parameters and
        style metadata.
    """
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
