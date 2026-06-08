"""``docs.missing-param-doc`` - documented function with an undocumented parameter.

Fires for each signature parameter that has no matching ``@param`` / ``Args:`` /
``Parameters`` entry in a public function's docstring. Skips ``self`` / ``cls``,
``_``-prefixed params, dunder methods, and functions without docstrings.
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
from gruffpy.rule.docs._docstring_parser import DocstringStyle, extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
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
    documented: set[str]
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
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for undocumented function parameters.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer.

        Returns:
            Findings for public documented functions with missing param entries.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for candidate in _param_doc_candidates(unit.tree):
            findings.extend(_missing_param_findings(unit, definition, candidate))
        return findings


def _param_doc_candidates(tree: ast.AST) -> list[_ParamDocCandidate]:
    candidates: list[_ParamDocCandidate] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        candidate = _param_doc_candidate(node)
        if candidate is not None:
            candidates.append(candidate)
    return candidates


def _param_doc_candidate(node: FunctionNode) -> _ParamDocCandidate | None:
    if _should_skip_param_doc_check(node):
        return None
    text = extract_docstring(node)
    if text is None:
        return None
    parsed = parse_docstring(text)
    if parsed is None:
        return None

    documented = {param.name for param in parsed.params if param.name}
    parameters = [param for param in signature_param_names(node) if not param.startswith("_")]
    missing = [param for param in parameters if param not in documented]
    if not missing:
        return None
    return _ParamDocCandidate(
        node=node,
        symbol=qualified_symbol(node, parent_chain(node)),
        missing=missing,
        documented=documented,
        style=parsed.style,
    )


def _should_skip_param_doc_check(node: FunctionNode) -> bool:
    return (
        not is_public(node.name)
        or is_dunder(node.name)
        or is_overload_stub(node)
        or is_property_setter_or_deleter(node)
    )


def _missing_param_findings(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _ParamDocCandidate,
) -> list[Finding]:
    if not candidate.documented:
        return [_missing_all_parameters_finding(unit, definition, candidate)]
    return [
        _missing_one_param_finding(unit, definition, candidate, param)
        for param in candidate.missing
    ]


def _missing_all_parameters_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _ParamDocCandidate,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {candidate.symbol!r} needs docstring entries describing its "
            f"{len(candidate.missing)} parameter(s)."
        ),
        file_path=unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.node.end_lineno,
        symbol=candidate.symbol,
        remediation=(
            "Document each parameter's purpose "
            "(Google ``Args:``, NumPy ``Parameters``, or Sphinx ``:param:``). "
            "Name what the parameter is for, not just its type."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"parameters": candidate.missing, "style": candidate.style.value},
    )


def _missing_one_param_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    candidate: _ParamDocCandidate,
    param: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {candidate.symbol!r} needs a docstring entry describing parameter {param!r}."
        ),
        file_path=unit.file.display_path,
        line=candidate.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=candidate.node.end_lineno,
        symbol=candidate.symbol,
        remediation=(
            f"Document {param!r}'s purpose in the function's docstring "
            f"(Google ``Args:``, NumPy ``Parameters``, or Sphinx ``:param:``). "
            f"Name what it is for, not just its type."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"parameter": param, "style": candidate.style.value},
    )
