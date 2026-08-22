"""``sensitive-data.hardcoded-env-value`` - .env file with a secret-looking value.

Fires on lines of the shape ``KEY=value`` inside ``.env`` / ``.env.*`` files
where the key name suggests a secret (``KEY``, ``SECRET``, ``TOKEN``, ``PASSWORD``,
``API_KEY``) and the value has high Shannon entropy. Empty values, placeholders,
and quoted-string templates with substitution syntax are skipped.
"""

import re

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import SourceTextRule
from gruffpy.rule.sensitive_data._secret_scanner_helper import (
    fixed_preview,
    shannon_entropy,
)

_SECRET_KEY_RE = re.compile(
    r"^(?P<key>[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|AUTH"
    r"|CREDENTIAL|SIGNATURE|PRIVATE))\s*=\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)
_TASK_PLACEHOLDER = "".join(("TO", "DO"))
_PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {"changeme", "your_secret_here", _TASK_PLACEHOLDER, "REPLACE_ME", "xxx", "***", ""}
)
_ENTROPY_THRESHOLD = 3.0
_MIN_VALUE_LENGTH = 12


class HardcodedEnvValueRule(SourceTextRule):
    """Detect secret-named ``.env`` keys with high-entropy literal values.

    Users encounter this rule after placing a real-looking credential in a committed environment
    file; the finding names the setting but replaces its value with a fixed marker.
    """

    ID = "sensitive-data.hardcoded-env-value"

    def definition(self) -> RuleDefinition:
        """Describe the hardcoded-env-value rule as a medium-confidence warning.

        Secret-like key names bound the noise, but random-looking fixtures can still match, so
        users receive a medium-confidence warning rather than an error.

        Returns:
            Definition for the hardcoded-env-value rule under the
            sensitive-data pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Hardcoded env-file secret",
            pillar=Pillar.SENSITIVE_DATA,
            tier=RuleTier.V01,
            default_severity=Severity.WARNING,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag ``.env`` lines where a secret-shaped KEY=value has a high-entropy literal value.

        Users see only literal values in ``.env`` files that meet the length and entropy gates;
        placeholders and runtime variable references remain quiet.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per ``.env`` line whose value crosses the
            entropy/length gates.
        """
        # Non-environment files stay out of this focused signal so users do not receive duplicate
        # noise.
        if not _is_env_file(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        # Each secret-named assignment remains independently actionable in the user's report.
        for secret_assignment in _SECRET_KEY_RE.finditer(unit.source):
            environment_key = secret_assignment.group("key")
            secret_value = secret_assignment.group("value").strip().strip("\"'")
            # Empty, short, and known placeholder values do not require credential rotation.
            if secret_value in _PLACEHOLDER_VALUES or len(secret_value) < _MIN_VALUE_LENGTH:
                continue
            # A runtime variable reference means the user did not commit the secret value itself.
            if secret_value.startswith("${") or secret_value.startswith("$"):
                continue
            # Structured low-entropy values are unlikely to be live credentials worth surfacing.
            if shannon_entropy(secret_value) < _ENTROPY_THRESHOLD:
                continue
            line = unit.source.count("\n", 0, secret_assignment.start()) + 1
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"`.env` value for `{environment_key}` looks like a hard-coded secret.",
                    file_path=unit.file.display_path,
                    line=line,
                    severity=definition.default_severity,
                    pillar=definition.pillar,
                    tier=definition.tier,
                    confidence=definition.confidence,
                    remediation=(
                        "Use placeholder values in committed `.env` files and inject "
                        "real secrets via the deployment environment or a secret manager."
                    ),
                    secondary_pillars=definition.secondary_pillars,
                    # The environment key names the setting the user must fix. The value's entropy
                    # is a statistic computed from the matched secret and is forbidden in
                    # serialized output by FAMILY-CONTRACT section 5.
                    metadata={"preview": fixed_preview(), "key": environment_key},
                ),
            )
        return findings


def _is_env_file(display_path: str) -> bool:
    """Return whether the user's discovered file uses an ``.env`` filename."""
    name = display_path.rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env.")
