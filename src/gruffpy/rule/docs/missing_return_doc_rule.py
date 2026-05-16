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
from gruffpy.rule.docs._docstring_parser import extract_docstring, parse_docstring
from gruffpy.rule.docs._helpers import (
    has_return_annotation,
    is_dunder,
    is_property_setter_or_deleter,
    is_public,
    returns_none_only,
)
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class MissingReturnDocRule(Rule):
    ID = "docs.missing-return-doc"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing return documentation",
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
            if not has_return_annotation(node):
                continue
            if returns_none_only(node):
                continue
            text = extract_docstring(node)
            if text is None:
                continue
            parsed = parse_docstring(text)
            if parsed is None:
                continue
            if parsed.returns is not None and (
                parsed.returns.description or parsed.returns.type_hint
            ):
                continue

            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has a non-None return type but no Returns section."
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
                        "Add a Returns / :returns: section describing the value's "
                        "shape and meaning."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"style": parsed.style.value},
                ),
            )
        return findings
