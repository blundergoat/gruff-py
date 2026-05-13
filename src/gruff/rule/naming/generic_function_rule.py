"""Vague function names that don't describe what the function does.

Flagged: ``process``, ``handle``, ``do``, ``run``, ``execute``, ``perform``,
``apply``, ``manage``, ``operate`` as standalone function/method names.
Configurable via ``genericFunctions`` per-rule option.

Allowed when used as a verb-prefix: ``process_payment``, ``handle_request``,
``execute_query`` are fine because they specify what is processed/handled.
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
from gruff.rule.naming._identifier_tokenizer import lower_tokens
from gruff.rule.rule import Rule
from gruff.rule.size._lines import parent_chain, qualified_symbol

_DEFAULT_GENERIC: tuple[str, ...] = (
    "process",
    "handle",
    "do",
    "run",
    "execute",
    "perform",
    "apply",
    "manage",
    "operate",
)


class GenericFunctionRule(Rule):
    ID = "naming.generic-function"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Generic function name",
            pillar=Pillar.NAMING,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
            default_options={"genericFunctions": list(_DEFAULT_GENERIC)},
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        settings = context.settings_for(definition)
        configured = settings.options.get("genericFunctions", list(_DEFAULT_GENERIC))
        if not isinstance(configured, list) or not all(isinstance(s, str) for s in configured):
            configured = list(_DEFAULT_GENERIC)
        generic = frozenset(configured)

        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            tokens = lower_tokens(node.name)
            if len(tokens) != 1:
                continue
            if tokens[0] not in generic:
                continue
            parents = parent_chain(node)
            symbol = qualified_symbol(node, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Function {symbol!r} has a generic name; "
                        "add a domain noun (e.g. ``process_payment``)."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    symbol=symbol,
                    remediation=f"Rename {node.name!r} to ``{node.name}_<noun>``.",
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"identifier": node.name},
                ),
            )
        return findings
