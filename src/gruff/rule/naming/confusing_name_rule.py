"""Vague class names: ``Handler``, ``Processor``, ``Manager``, ``Util``,
``Helper``, ``Data``, ``Info``, ``Service`` used as standalone class names.

Allowed as a suffix (``UserService``, ``EventHandler``, ``ImageProcessor``).
Configurable via the ``confusingNames`` per-rule option.
"""

import ast

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.definition import RuleDefinition
from gruff.rule.rule import Rule

_DEFAULT_CONFUSING: tuple[str, ...] = (
    "Handler",
    "Processor",
    "Manager",
    "Util",
    "Utils",
    "Helper",
    "Helpers",
    "Data",
    "Info",
    "Service",
    "Stuff",
    "Thing",
    "Object",
    "Item",
)


class ConfusingNameRule(Rule):
    ID = "naming.confusing-name"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Confusing class name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"confusingNames": list(_DEFAULT_CONFUSING)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        configured = settings.options.get("confusingNames", list(_DEFAULT_CONFUSING))
        if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
            configured = list(_DEFAULT_CONFUSING)
        confusing = frozenset(configured)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in confusing:
                findings.append(
                    Finding(
                        rule_id=definition.id,
                        message=(
                            f"Class name {node.name!r} is vague; "
                            "use a domain-specific suffix (e.g. ``UserService``)."
                        ),
                        file_path=unit.file.display_path,
                        line=node.lineno,
                        severity=definition.default_severity,
                        pillar=definition.pillar,
                        tier=definition.tier,
                        confidence=definition.confidence,
                        end_line=node.end_lineno,
                        symbol=node.name,
                        remediation=f"Rename {node.name!r} to add a domain prefix.",
                        secondary_pillars=definition.secondary_pillars,
                        metadata={"identifier": node.name},
                    ),
                )
        return findings
