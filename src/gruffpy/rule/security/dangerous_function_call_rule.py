"""``security.dangerous-function-call`` - eval / exec / compile / dynamic __import__.

Fires unconditionally on ``eval``, ``exec``, and ``compile``. ``__import__``
is only flagged when called with a non-literal first argument (literal
imports are equivalent to a normal import statement).
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
    is_string_literal,
)

_UNCONDITIONAL_DANGEROUS: frozenset[str] = frozenset({"eval", "exec", "compile"})
_SOURCE_NEEDLES: tuple[str, ...] = ("eval", "exec", "compile", "__import__")


class DangerousFunctionCallRule(Rule):
    """Detect calls to `eval`, `exec`, `compile`, and `__import__` with non-literal arguments."""

    ID = "security.dangerous-function-call"

    def definition(self) -> RuleDefinition:
        """Describe the dangerous-function-call rule as a high-confidence ERROR.

        ERROR severity reflects the risk when the matched input is unsafe.
        High confidence describes the exact built-in target match; the rule
        does not establish input provenance.

        Returns:
            Definition for the dangerous-function-call rule under the
            security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Dangerous function call",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag every ``eval``/``exec``/``compile`` call, plus dynamic ``__import__``.

        Literal ``__import__("os")`` is treated as a normal import and
        skipped; ``__import__(name_var)`` is flagged. The other targets fire
        unconditionally because they always represent code-execution surface.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per matching call site.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        return [_dangerous_call_finding(unit, definition, node, kind) for node, kind in _dangerous_calls(unit.tree)]


def _dangerous_calls(tree: ast.AST) -> list[tuple[ast.Call, str]]:
    """Collect call sites matching the dangerous-call syntax checks.

    Args:
        tree: Syntax subtree to search, including nested scopes.

    Returns:
        Call and target-label pairs in AST traversal order; an empty list when none match.
    """
    findings: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        kind = _dangerous_call_kind(node)
        if kind is not None:
            findings.append((node, kind))
    return findings


def _dangerous_call_kind(node: ast.Call) -> str | None:
    """Identify a dangerous target from its spelling and argument syntax.

    Listed execution targets match regardless of arguments; the import target requires a first positional argument that is not a string literal.

    Args:
        node: Call to check for a listed target or a dynamic import argument.

    Returns:
        Matched target name, or None for other calls or imports without a nonliteral first positional argument.
    """
    target = call_target_name(node)
    if target in _UNCONDITIONAL_DANGEROUS:
        return target
    if target != "__import__":
        return None
    first = node.args[0] if node.args else None
    if first is not None and not is_string_literal(first):
        return "__import__"
    return None


def _dangerous_call_finding(
    unit: AnalysisUnit,
    definition: RuleDefinition,
    node: ast.Call,
    kind: str,
) -> Finding:
    """Build the finding for a matched dangerous call.

    Args:
        unit: Analysis unit providing the displayed file path.
        definition: Rule identity, severity, and classification to copy into the finding.
        node: Matched call supplying the finding's source span.
        kind: Target label returned by the dangerous-call check.

    Returns:
        Finding with the call location and target label in its message and metadata.
    """
    return Finding(
        rule_id=definition.id,
        message=(f"Dangerous call to `{kind}()` - arbitrary code execution surface."),
        file_path=unit.file.display_path,
        line=node.lineno,
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=node.end_lineno,
        remediation=(
            "Replace with structured deserialisation or an explicit dispatch "
            "table. If you genuinely need dynamic code, isolate it in a "
            "sandboxed subprocess."
        ),
        secondary_pillars=definition.secondary_pillars,
        metadata={"target": kind},
    )
