"""``docs.missing-class-docstring`` — ``class Foo`` without a docstring.

Exempts Protocols, ABCs, TypedDicts, NamedTuples, Enum-like bases, and
``@dataclass``-decorated classes when ``class_dataclass_exempt`` is set
in the rule's options (default true — dataclasses usually document fields
via ``Attributes:`` on the class but many use them as plain DTOs).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._python_dynamism import has_dataclass_decorator, has_framework_base
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.docs._docstring_parser import extract_docstring
from gruffpy.rule.docs._helpers import is_dunder
from gruffpy.rule.rule import Rule
from gruffpy.rule.size._lines import parent_chain, qualified_symbol


class MissingClassDocstringRule(Rule):
    ID = "docs.missing-class-docstring"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Missing class docstring",
            pillar=Pillar.DOCUMENTATION,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
            default_options={"class_dataclass_exempt": True},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        dataclass_exempt = settings.options.get(
            "class_dataclass_exempt",
            definition.default_options["class_dataclass_exempt"],
        )

        findings: list[Finding] = []
        for node in _undocumented_classes(unit.tree, dataclass_exempt=bool(dataclass_exempt)):
            findings.append(_missing_class_docstring_finding(unit, definition, node))
        return findings


def _undocumented_classes(tree: ast.AST, *, dataclass_exempt: bool) -> list[ast.ClassDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef)
        and _should_report_missing_class_docstring(node, dataclass_exempt=dataclass_exempt)
    ]


def _should_report_missing_class_docstring(
    node: ast.ClassDef,
    *,
    dataclass_exempt: bool,
) -> bool:
    if is_dunder(node.name):
        return False
    if extract_docstring(node) is not None:
        return False
    if has_framework_base(node):
        return False
    return not (dataclass_exempt and has_dataclass_decorator(node))


def _missing_class_docstring_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.ClassDef,
) -> Finding:
    symbol = qualified_symbol(node, parent_chain(node))
    return Finding(
        rule_id=definition.id,
        message=f"Class {symbol!r} has no docstring.",
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        symbol=symbol,
        remediation=("Add a docstring describing the class's role and any non-obvious invariants."),
        secondary_pillars=definition.secondary_pillars,
        metadata={},
    )
