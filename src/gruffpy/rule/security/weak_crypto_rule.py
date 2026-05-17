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
    has_security_smell,
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
            candidate = _weak_crypto_call(node)
            if candidate is None:
                continue
            call, algorithm = candidate
            findings.append(_finding_for_call(definition, unit.file.display_path, call, algorithm))
        return findings


def _weak_crypto_call(node: ast.AST) -> tuple[ast.Call, str] | None:
    if not isinstance(node, ast.Call):
        return None
    target = call_target_name(node)
    if target is None:
        return None
    algorithm = _weak_algorithm(target)
    if algorithm is None or not _has_security_context_smell(node):
        return None
    return node, algorithm


def _finding_for_call(
    definition: RuleDefinition,
    file_path: str,
    call: ast.Call,
    algorithm: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"`hashlib.{algorithm}` used in a security-smelling context — "
            f"prefer SHA-256+ or a password-hashing KDF."
        ),
        file_path=file_path,
        line=call.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=call.end_lineno,
        remediation=(
            "Use ``hashlib.sha256``/``sha512`` for content hashing or "
            "``hashlib.scrypt`` / ``argon2`` / ``bcrypt`` for password storage."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"algorithm": algorithm},
    )


def _weak_algorithm(target: str) -> str | None:
    """Return the algorithm name when *target* references hashlib.md5/sha1."""
    if target in {"hashlib.md5", "hashlib.sha1"}:
        return target.split(".")[-1]
    if target in _WEAK_ALGORITHMS:
        # `from hashlib import md5` style — bare name match.
        return target
    return None


def _has_security_context_smell(call: ast.Call) -> bool:
    """True when *call* arguments or enclosing assignment target smell security."""
    return _has_security_smelling_argument(call) or _has_security_smelling_parent(call)


def _has_security_smelling_argument(call: ast.Call) -> bool:
    for arg in call.args:
        for node in ast.walk(arg):
            if isinstance(node, ast.Name) and has_security_smell(node.id):
                return True
    return False


def _has_security_smelling_parent(call: ast.Call) -> bool:
    parent = getattr(call, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.Assign):
            return _has_security_smelling_target(parent.targets)
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return bool(has_security_smell(parent.name))
        parent = getattr(parent, "parent", None)
    return False


def _has_security_smelling_target(targets: list[ast.expr]) -> bool:
    return any(isinstance(target, ast.Name) and has_security_smell(target.id) for target in targets)
