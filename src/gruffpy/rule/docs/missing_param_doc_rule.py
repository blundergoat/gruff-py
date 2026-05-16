"""``docs.missing-param-doc`` — documented function with an undocumented parameter.

Fires for each signature parameter that has no matching ``@param`` / ``Args:`` /
``Parameters`` entry in a public function's docstring. Skips ``self`` / ``cls``,
``_``-prefixed params, dunder methods, and functions without docstrings.
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
from gruffpy.rule.docs._docstring_parser import extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
    signature_param_names,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class MissingParamDocRule(Rule):
    ID = "docs.missing-param-doc"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing parameter documentation",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not is_public(node.name) or is_dunder(node.name):
                continue
            if is_overload_stub(node) or is_property_setter_or_deleter(node):
                continue
            text = extract_docstring(node)
            if text is None:
                continue
            parsed = parse_docstring(text)
            if parsed is None:
                continue
            documented = {p.name for p in parsed.params if p.name}
            params = signature_param_names(node)
            params = [p for p in params if not p.startswith("_")]
            if not params:
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            missing = [param for param in params if param not in documented]
            if not missing:
                continue
            if not documented:
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Function {symbol!r} has no docstring entries for "
                            f"{len(missing)} parameter(s)."
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
                            "Document the function parameters "
                            "(Google ``Args:``, NumPy ``Parameters``, or Sphinx ``:param:``)."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"parameters": missing, "style": parsed.style.value},
                    ),
                )
                continue
            for param in missing:
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Function {symbol!r} has no docstring entry for parameter {param!r}."
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
                            f"Document {param!r} in the function's docstring "
                            f"(Google ``Args:``, NumPy ``Parameters``, or Sphinx ``:param:``)."
                        ),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"parameter": param, "style": parsed.style.value},
                    ),
                )
        return findings
