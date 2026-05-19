"""``security.insecure-random`` — ``random.*`` used for security-sensitive values.

Fires on ``random.random / randint / choice / randbytes / getrandbits / uniform``
when the call's assignment target or enclosing function name suggests
security material. The standard library's ``random`` module is not
cryptographically secure; use ``secrets`` instead.
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule
from gruffpy.rule.security._security_node_helper import (
    call_target_name,
    has_security_smell,
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
    """Detect `random.*` calls used to produce security-sensitive values like tokens or passwords."""

    ID = "security.insecure-random"

    def definition(self) -> RuleDefinition:
        """Describe the insecure-random rule as a medium-confidence warning.

        Medium confidence because ``random`` is fine for simulations,
        sampling, and tests; the heuristic only fires when the *use*
        smells security-sensitive.

        Returns:
            Definition for the insecure-random rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Insecure random source",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``random.*`` calls inside security-smelling enclosing context.

        Walks up the call's parent chain: if the assignment target or
        enclosing function name passes ``has_security_smell`` (``token``,
        ``password``, ``api_key``, etc.), the call is flagged with a
        ``secrets``-module remediation.

        Args:
            unit: Parsed source file to inspect (with parent links).
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per ``random.X`` call in a security-smelling scope.
        """
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
            if not _has_security_context_smell(node):
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


def _has_security_context_smell(call: ast.Call) -> bool:
    parent = getattr(call, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.Assign):
            return any(isinstance(t, ast.Name) and has_security_smell(t.id) for t in parent.targets)
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return has_security_smell(parent.name)
        parent = getattr(parent, "parent", None)
    return False
