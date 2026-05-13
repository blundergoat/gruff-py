"""``test-quality.mystery-guest`` — test depends on opaque external state.

Heuristic: the test calls ``open(...)``, ``requests.*``, ``urllib.*``,
``socket.*``, or other clear network / filesystem / DB I/O without using a
fixture-like setup. Tests that pull from real external sources are non-hermetic
and slow.
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
from gruff.rule.security._security_node_helper import call_target_name
from gruff.rule.size._lines import parent_chain, qualified_symbol
from gruff.rule.test_quality._test_quality_node_helper import (
    test_functions,
    walk_test_body,
)

_MYSTERY_PREFIXES: frozenset[str] = frozenset(
    {"requests", "urllib", "urllib3", "socket", "httpx", "aiohttp", "ftplib", "smtplib"}
)
_MYSTERY_LEAVES: frozenset[str] = frozenset({"open", "popen"})


class MysteryGuestRule(Rule):
    ID = "test-quality.mystery-guest"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Mystery guest in test",
            pillar=Pillar.TEST_QUALITY,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for fn, _scope in test_functions(unit):
            target_found = _find_mystery_target(fn)
            if target_found is None:
                continue
            parents = parent_chain(fn)
            symbol = qualified_symbol(fn, parents)
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"Test {symbol!r} touches external state via `{target_found}` — "
                        f"non-hermetic dependency."
                    ),
                    file_path=unit.file.display_path,
                    line=fn.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=fn.end_lineno,
                    symbol=symbol,
                    remediation=(
                        "Mock the I/O boundary or use a tmp_path fixture for filesystem "
                        "interactions."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target_found},
                ),
            )
        return findings


def _find_mystery_target(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    for node in walk_test_body(fn):
        if not isinstance(node, ast.Call):
            continue
        target = call_target_name(node)
        if target is None:
            continue
        if target in _MYSTERY_LEAVES:
            return target
        root = target.split(".")[0]
        if root in _MYSTERY_PREFIXES:
            return target
    return None
