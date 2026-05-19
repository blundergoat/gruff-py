"""``security.shell-injection`` — subprocess with ``shell=True`` or ``os.system`` on dynamic input.

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


class ShellInjectionRule(Rule):
    ID = "security.shell-injection"

    def definition(self) -> RuleDefinition:
        """Describe the shell-injection rule as a high-confidence ERROR.

        ERROR severity because the pattern is rarely accidental: someone had
        to write ``shell=True`` with a non-literal command. High confidence
        because the call shape is precise (target name + ``shell=True``
        kwarg + dynamic first arg).

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
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag subprocess ``shell=True`` with dynamic input, and ``os.system``/``os.popen`` calls.

        Static command strings to ``subprocess(..., shell=True)`` and
        ``os.system("...")`` are skipped (no injection surface). The
        subprocess targets covered include ``run``/``call``/``check_call``/
        ``check_output``/``Popen``/``getoutput``/``getstatusoutput``.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per shell-injection call site.
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
                    remediation=(
                        "Pass argv as a list with ``shell=False`` (the default), or "
                        "use ``shlex.quote`` if a shell really is required."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target},
                ),
            )
        return findings


def _shell_injection_label(target: str, call: ast.Call) -> str | None:
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
    return isinstance(node, ast.Constant) and node.value is True
