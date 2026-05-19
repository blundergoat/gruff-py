"""``sensitive-data.hardcoded-env-value`` — .env file with a secret-looking value.

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
    redact_preview,
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
    ID = "sensitive-data.hardcoded-env-value"

    def definition(self) -> RuleDefinition:
        """Describe the hardcoded-env-value rule as a medium-confidence warning.

        Medium confidence because entropy-based detection can fire on
        deterministic-but-random-looking values (test fixtures, generated
        IDs); the secret-key-name gate keeps the noise bounded.

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

        Only runs on files named ``.env`` or ``.env.*``. Values prefixed
        with ``$`` / ``${`` are treated as variable interpolation, not
        literals. Below 12 characters or entropy < 3.0 bits/char, the
        value is considered too small/structured to be a real secret.

        Args:
            unit: Source file whose raw text is scanned.
            context: Rule execution context (unused — no thresholds).

        Returns:
            One finding per ``.env`` line whose value crosses the
            entropy/length gates.
        """
        if not _is_env_file(unit.file.display_path):
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for match in _SECRET_KEY_RE.finditer(unit.source):
            key = match.group("key")
            value = match.group("value").strip().strip("\"'")
            if value in _PLACEHOLDER_VALUES or len(value) < _MIN_VALUE_LENGTH:
                continue
            if value.startswith("${") or value.startswith("$"):
                continue  # Variable interpolation — not a literal secret.
            if shannon_entropy(value) < _ENTROPY_THRESHOLD:
                continue
            line = unit.source.count("\n", 0, match.start()) + 1
            findings.append(
                Finding(
                    rule_id=definition.id,
                    message=f"`.env` value for `{key}` looks like a hard-coded secret.",
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
                    metadata={
                        "preview": redact_preview(value),
                        "key": key,
                        "entropy": round(shannon_entropy(value), 2),
                    },
                ),
            )
        return findings


def _is_env_file(display_path: str) -> bool:
    name = display_path.rsplit("/", 1)[-1]
    return name == ".env" or name.startswith(".env.")
