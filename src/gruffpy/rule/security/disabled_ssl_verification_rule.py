"""``security.disabled-ssl-verification`` — explicit SSL/TLS verify disablement.

Catches:

- ``requests.get/post/.../request(..., verify=False)``
- ``ssl._create_unverified_context()``
- ``urllib3.disable_warnings()``
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
    is_false_constant,
)

_REQUESTS_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "delete", "patch", "head", "options", "request"}
)


class DisabledSslVerificationRule(Rule):
    ID = "security.disabled-ssl-verification"

    def definition(self) -> RuleDefinition:
        return RuleDefinition(
            id=self.ID,
            name="Disabled SSL verification",
            pillar=Pillar.SECURITY,
            tier=RuleTier.V01,
            default_severity=Severity.ERROR,
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
            reason = _ssl_verification_disabled_reason(target, node)
            if reason is None:
                continue
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"{reason} disables TLS certificate verification.",
                    file_path=unit.file.display_path,
                    line=node.lineno,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    end_line=node.end_lineno,
                    remediation=(
                        "Use a properly verified TLS context. If you need a custom trust "
                        "store, configure CA bundles instead of disabling verification."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    metadata={"target": target, "reason": reason},
                ),
            )
        return findings


def _ssl_verification_disabled_reason(target: str, call: ast.Call) -> str | None:
    if target.startswith("requests."):
        last = target.split(".")[-1]
        if last in _REQUESTS_METHODS:
            verify = call_keyword(call, "verify")
            if verify is not None and is_false_constant(verify):
                return f"`{target}(verify=False)`"
    if target in {"ssl._create_unverified_context", "_create_unverified_context"}:
        return "`ssl._create_unverified_context()`"
    if target in {"urllib3.disable_warnings", "disable_warnings"}:
        return "`urllib3.disable_warnings()`"
    return None
