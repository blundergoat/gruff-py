"""``security.weak-crypto`` — MD5 / SHA1 used for security-smelling work.

Fires on ``hashlib.md5(...)`` or ``hashlib.sha1(...)`` when the surrounding
context suggests crypto rather than non-crypto hashing (cache key, content
digest). Heuristic: an argument or the assignment target contains a
security-smelling identifier (``password``, ``token``, ``signature``, etc.).
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
    name_smells_security,
)

_WEAK_ALGORITHMS: frozenset[str] = frozenset({"md5", "sha1"})


class WeakCryptoRule(Rule):
    ID = "security.weak-crypto"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Weak cryptographic hash",
            pillar=Pillar.SECURITY,
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
            if not isinstance(node, ast.Call):
                continue
            target = call_target_name(node)
            if target is None:
                continue
            algorithm = _weak_algorithm(target)
            if algorithm is None:
                continue
            if not _context_smells_security(node):
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=(
                        f"`hashlib.{algorithm}` used in a security-smelling context — "
                        f"prefer SHA-256+ or a password-hashing KDF."
                    ),
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Use ``hashlib.sha256``/``sha512`` for content hashing or "
                        "``hashlib.scrypt`` / ``argon2`` / ``bcrypt`` for password storage."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"algorithm": algorithm},
                ),
            )
        return findings


def _weak_algorithm(target: str) -> str | None:
    """Return the algorithm name when *target* references hashlib.md5/sha1."""
    if target in {"hashlib.md5", "hashlib.sha1"}:
        return target.split(".")[-1]
    if target in _WEAK_ALGORITHMS:
        # `from hashlib import md5` style — bare name match.
        return target
    return None


def _context_smells_security(call: ast.Call) -> bool:
    """True when *call* arguments or enclosing assignment target smell security."""
    for arg in call.args:
        for node in ast.walk(arg):
            if isinstance(node, ast.Name) and name_smells_security(node.id):
                return True
    parent = getattr(call, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.Assign):
            for target in parent.targets:
                if isinstance(target, ast.Name) and name_smells_security(target.id):
                    return True
            return False
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return bool(name_smells_security(parent.name))
        parent = getattr(parent, "parent", None)
    return False
