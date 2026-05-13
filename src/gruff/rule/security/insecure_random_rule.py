"""``security.insecure-random`` — ``random.*`` used for security-sensitive values.

Fires on ``random.random / randint / choice / randbytes / getrandbits / uniform``
when the call's assignment target or enclosing function name suggests
security material. The standard library's ``random`` module is not
cryptographically secure; use ``secrets`` instead.
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
from gruff.rule.security._security_node_helper import (
    call_target_name,
    name_smells_security,
)

_RANDOM_METHODS: frozenset[str] = frozenset(
    {
        "random",
        "randint",
        "choice",
        "choices",
        "sample",
        "randbytes",
        "getrandbits",
        "uniform",
        "randrange",
    }
)


class InsecureRandomRule(Rule):
    ID = "security.insecure-random"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Insecure random source",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = call_target_name(node)
            if target is None:
                continue
            if not _is_random_call(target):
                continue
            if not _context_smells_security(node):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"`{target}` used for a security-smelling value — "
                        f"`random` is not cryptographically secure."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Use the ``secrets`` module: ``secrets.token_hex(32)``, "
                        "``secrets.choice(...)``, ``secrets.randbelow(...)``."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target},
                ),
            )
        return findings


def _is_random_call(target: str) -> bool:
    if target.startswith("random."):
        return target.split(".", 1)[1] in _RANDOM_METHODS
    return False


def _context_smells_security(call: ast.Call) -> bool:
    parent = getattr(call, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.Assign):
            return any(
                isinstance(t, ast.Name) and name_smells_security(t.id) for t in parent.targets
            )
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return name_smells_security(parent.name)
        parent = getattr(parent, "parent", None)
    return False
