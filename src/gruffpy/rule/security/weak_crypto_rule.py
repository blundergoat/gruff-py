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
from gruffpy.rule.security._security_metadata import finding_security_metadata
from gruffpy.rule.security._security_node_helper import (
    call_target_name,
    has_security_smell,
)

_WEAK_ALGORITHMS: frozenset[str] = frozenset({"md5", "sha1"})
_FAST_PASSWORD_HASH_ALGORITHMS: frozenset[str] = frozenset({"sha256", "sha512"})
_PASSWORD_HASH_TOKENS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "private_key",
    }
)


class WeakCryptoRule(Rule):
    ID = "security.weak-crypto"

    def definition(self) -> RuleDefinition:
        """Describe the weak-crypto rule as a high-confidence warning.

        High confidence because the call shape (``hashlib.md5/sha1``) is
        exact and the security-context check trims away the cache-key and
        content-digest uses where MD5/SHA1 are acceptable.

        Returns:
            Definition for the weak-crypto rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Weak cryptographic hash",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.HIGH,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag MD5/SHA1 in security contexts, and SHA256/SHA512 used for password hashing.

        Two patterns trigger findings:
        - ``hashlib.md5/sha1(...)`` when the argument or enclosing scope
          carries a security-smelling name (``token``, ``signature``, etc.);
        - ``hashlib.sha256/sha512(...)`` when the surrounding context smells
          like password hashing — fast cryptographic hashes are too quick
          for password storage and should be replaced with a KDF
          (``scrypt``/``argon2``/``bcrypt``).

        Args:
            unit: Parsed source file to inspect (with parent links).
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per weak-algorithm-in-security-context call.
        """
        if unit.tree is None:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            candidate = _weak_crypto_call(node)
            if candidate is None:
                continue
            call, algorithm, source_label = candidate
            findings.append(
                _finding_for_call(definition, unit.file.display_path, call, algorithm, source_label)
            )
        return findings


def _weak_crypto_call(node: ast.AST) -> tuple[ast.Call, str, str] | None:
    if not isinstance(node, ast.Call):
        return None
    target = call_target_name(node)
    if target is None:
        return None
    algorithm = _weak_algorithm(target)
    if algorithm is not None and _has_security_context_smell(node):
        return node, algorithm, "security-sensitive-material"
    algorithm = _fast_password_hash_algorithm(target)
    if algorithm is None or not _has_password_hashing_context_smell(node):
        return None
    return node, algorithm, "password-material"


def _finding_for_call(
    definition: RuleDefinition,
    file_path: str,
    call: ast.Call,
    algorithm: str,
    source_label: str,
) -> Finding:
    password_hashing = algorithm in _FAST_PASSWORD_HASH_ALGORITHMS
    remediation = (
        "Use ``hashlib.scrypt`` / ``argon2`` / ``bcrypt`` for password storage."
        if password_hashing
        else (
            "Use ``hashlib.sha256``/``sha512`` for content hashing or "
            "``hashlib.scrypt`` / ``argon2`` / ``bcrypt`` for password storage."
        )
    )
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
        remediation=remediation,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "algorithm": algorithm,
            **finding_security_metadata(
                definition.id,
                source_label=source_label,
                sink_label="fast-hash",
            ),
        },
    )


def _weak_algorithm(target: str) -> str | None:
    """Return the algorithm name when *target* references hashlib.md5/sha1."""
    if target in {"hashlib.md5", "hashlib.sha1"}:
        return target.split(".")[-1]
    if target in _WEAK_ALGORITHMS:
        # `from hashlib import md5` style — bare name match.
        return target
    return None


def _fast_password_hash_algorithm(target: str) -> str | None:
    """Return the algorithm name when *target* references hashlib.sha256/sha512."""
    if target in {"hashlib.sha256", "hashlib.sha512"}:
        return target.split(".")[-1]
    if target in _FAST_PASSWORD_HASH_ALGORITHMS:
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


def _has_password_hashing_context_smell(call: ast.Call) -> bool:
    return _has_password_hashing_argument(call) or _has_password_hashing_parent(call)


def _has_password_hashing_argument(call: ast.Call) -> bool:
    for arg in call.args:
        for node in ast.walk(arg):
            name = _security_name(node)
            if name is not None and _has_password_hashing_smell(name):
                return True
    return False


def _has_password_hashing_parent(call: ast.Call) -> bool:
    parent = getattr(call, "parent", None)
    while parent is not None:
        if isinstance(parent, ast.Assign):
            return _has_password_hashing_target(parent.targets)
        if isinstance(parent, ast.FunctionDef | ast.AsyncFunctionDef):
            return bool(_has_password_hashing_smell(parent.name))
        parent = getattr(parent, "parent", None)
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
    return any(
        name is not None and has_security_smell(name)
        for target in targets
        for name in [_target_security_name(target)]
    )


def _has_password_hashing_target(targets: list[ast.expr]) -> bool:
    return any(
        name is not None and _has_password_hashing_smell(name)
        for target in targets
        for name in [_target_security_name(target)]
    )


def _target_security_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _security_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _has_password_hashing_smell(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in _PASSWORD_HASH_TOKENS)
