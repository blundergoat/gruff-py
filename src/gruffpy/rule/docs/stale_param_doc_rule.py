"""``docs.stale-param-doc`` — docstring documents a parameter not in the signature.

High-confidence rename / leftover detector. Skips ``*args``/``**kwargs`` wildcard
matches and the implicit ``self`` / ``cls`` slot.
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
from gruffpy.rule.docs._helpers import is_property_setter_or_deleter, signature_param_names
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class StaleParamDocRule(Rule):
    ID = "docs.stale-param-doc"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Stale parameter documentation",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if is_overload_stub(node) or is_property_setter_or_deleter(node):
                continue
            text = extract_docstring(node)
            if text is None:
                continue
            parsed = parse_docstring(text)
            if parsed is None or not parsed.params:
                continue
            signature_names = set(signature_param_names(node))
            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)

            for documented in parsed.params:
                if documented.name is None:
                    continue
                if documented.name in signature_names:
                    continue
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Function {symbol!r} docstring documents parameter "
                            f"{documented.name!r}, which is not in the signature."
                        ),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=symbol,
                        remediation=("Remove the stale entry or rename it to match the signature."),
                        secondary_pillars=definition.secondary_pillars,
                        metadata={
                            "parameter": documented.name,
                            "style": parsed.style.value,
                        },
                    ),
                )
        return findings
