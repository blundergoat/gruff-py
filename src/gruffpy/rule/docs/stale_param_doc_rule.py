"""``docs.stale-param-doc`` — docstring documents a parameter not in the signature.

High-confidence rename / leftover detector. Skips ``*args``/``**kwargs`` wildcard
matches and the implicit ``self`` / ``cls`` slot.
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
from gruffpy.rule.docs._helpers import is_property_setter_or_deleter, signature_param_names
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol

FunctionNode = ast.FunctionDef | ast.AsyncFunctionDef


@dataclass(frozen=True, slots=True)
class _StaleParam:
    """Documented parameter entry that no longer exists in the signature."""

    node: FunctionNode
    symbol: str
    name: str
    style: DocstringStyle


class StaleParamDocRule(Rule):
    """Detect function docstrings that mention stale parameter names."""

    ID = "docs.stale-param-doc"

    def definition(self) -> RuleDefinition:
        """Return the rule metadata used by the registry and reporters.

        Returns:
            Definition for the stale parameter documentation rule.
        """
        return RuleDefinition(
            id=self.ID,
            name="Stale parameter documentation",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Analyze a Python module for stale docstring parameter entries.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context supplied by the analyzer.

        Returns:
            Findings for documented parameters absent from function signatures.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        return [
            _stale_param_finding(unit, definition, stale_param)
            for stale_param in _stale_params(unit.tree)
        ]


def _stale_params(tree: ast.AST) -> list[_StaleParam]:
    stale: list[_StaleParam] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        stale.extend(_stale_params_for_function(node))
    return stale


def _stale_params_for_function(node: FunctionNode) -> list[_StaleParam]:
    if is_overload_stub(node) or is_property_setter_or_deleter(node):
        return []
    text = extract_docstring(node)
    if text is None:
        return []
    parsed = parse_docstring(text)
    if parsed is None or not parsed.params:
        return []

    signature_names = set(signature_param_names(node))
    symbol = qualified_symbol(node, parent_chain(node))
    return [
        _StaleParam(node=node, symbol=symbol, name=param.name, style=parsed.style)
        for param in parsed.params
        if param.name is not None and _normalise_param_name(param.name) not in signature_names
    ]


def _normalise_param_name(name: str) -> str:
    # Docstring parsers preserve `*args` / `**kwargs` literally; signature_param_names
    # returns the bare identifier. Strip the leading `*` / `**` so a docstring
    # entry for `*keys` matches a signature varargs slot named `keys`.
    return name.lstrip("*")


def _stale_param_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    stale_param: _StaleParam,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Function {stale_param.symbol!r} docstring documents parameter "
            f"{stale_param.name!r}, which is not in the signature."
        ),
        file_path=unit.file.display_path,
        line=stale_param.node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=stale_param.node.end_lineno,
        symbol=stale_param.symbol,
        remediation=("Remove the stale entry or rename it to match the signature."),
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "parameter": stale_param.name,
            "style": stale_param.style.value,
        },
    )
