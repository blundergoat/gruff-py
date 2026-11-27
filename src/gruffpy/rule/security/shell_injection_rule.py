"""``security.shell-injection`` - subprocess with ``shell=True`` or ``os.system`` on dynamic input.

Catches:

- ``subprocess.run/call/check_call/check_output/Popen(..., shell=True)`` where
  the command argument is not a static string literal
- ``os.system(<non-literal>)`` / ``os.popen(<non-literal>)``
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
    call_keyword,
    call_target_name,
    is_string_literal,
)

_SUBPROCESS_TARGETS: frozenset[str] = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)
_OS_SHELL_TARGETS: frozenset[str] = frozenset({"os.system", "os.popen"})
_SOURCE_NEEDLES: tuple[str, ...] = ("subprocess", "system", "popen")


class ShellInjectionRule(Rule):
    """Detect `subprocess.*(shell=True)` or `os.system`/`popen` calls receiving dynamic commands."""

    ID = "security.shell-injection"

    def definition(self) -> RuleDefinition:
        """Describe the shell-injection rule as a high-confidence ERROR.

        Nonliteral commands at supported subprocess or os shell-call shapes can allow shell injection.

        Returns:
            Definition for the shell-injection rule under the security pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Shell injection",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
            confidence=Confidence.HIGH,
            # Off unless a project enables it: right on 3 of 7 judged findings in the 0.6.0 measurement; too few to delete on (ADR-029).
            default_enabled=False,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag dynamic commands passed to supported subprocess targets with shell=True or to calls spelled os.system or os.popen.

        Subprocess calls require literal shell=True. Both groups require a first positional command other than a string literal.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per matched call, or an empty list when parsing is unavailable or none match.
        """
        if unit.tree is None or not any(needle in unit.source for needle in _SOURCE_NEEDLES):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for node in ast.walk(unit.tree):
            if not isinstance(node, ast.Call):
                continue
            target = call_target_name(node)
            if target is None:
                continue
            label = _shell_injection_label(target, node)
            if label is None:
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"`{label}` runs a non-literal command through a shell.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=("Pass argv as a list with ``shell=False`` (the default), or use ``shlex.quote`` if a shell really is required."),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target},
                ),
            )
        return findings


def _shell_injection_label(target: str, call: ast.Call) -> str | None:
    """Classify a supported shell call with a first positional argument other than a string literal.

    Configured subprocess targets require literal shell=True.
    Configured os shell targets are checked regardless of that keyword.

    Args:
        target: Resolved call-target spelling to compare with the configured target sets.
        call: Call supplying positional arguments and the named shell option.

    Returns:
        A display label for a matching call, or None when its target, arguments or shell option fail the rule's checks.
    """
    if target in _SUBPROCESS_TARGETS:
        shell_kw = call_keyword(call, "shell")
        if shell_kw is None or not _is_true_constant(shell_kw):
            return None
        if not call.args:
            return None
        if is_string_literal(call.args[0]):
            return None
        return f"{target}(..., shell=True)"
    if target in _OS_SHELL_TARGETS:
        if not call.args:
            return None
        if is_string_literal(call.args[0]):
            return None
        return f"{target}(...)"
    return None


def _is_true_constant(node: ast.expr) -> bool:
    """Recognize the literal boolean True in an expression.

    Args:
        node: Expression supplying a possible boolean constant.

    Returns:
        True only for an AST constant whose value is the True singleton.
    """
    return isinstance(node, ast.Constant) and node.value is True
