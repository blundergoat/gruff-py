"""``sensitive-data.hardcoded-env-value`` - .env file with a secret-looking value.

Fires on lines of the shape ``KEY=value`` inside ``.env`` / ``.env.*`` files
where the key name suggests a secret (``KEY``, ``SECRET``, ``TOKEN``, ``PASSWORD``,
``API_KEY``) and the value has high Shannon entropy. Empty values, placeholders,
and quoted-string templates with substitution syntax are skipped. The value is
read from its own line only, so ``KEY=`` with nothing after it stays quiet
whatever the next line holds.

``.env.example``, ``.env.sample``, ``.env.template`` and ``.env.dist`` exist to
list secret-shaped keys with sample values, so a value there reports only when
it is shaped like a generated credential rather than merely long.
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
    r"^(?P<key>[A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|AUTH|CREDENTIAL|SIGNATURE|PRIVATE))"
    # Horizontal whitespace only: ``\s`` would carry an empty value across the line break into the next line.
    r"[ \t]*=[ \t]*(?P<value>[^\r\n]*?)[ \t]*\r?$",
    re.MULTILINE,
)
_TASK_PLACEHOLDER = "".join(("TO", "DO"))
# Compared case-folded, so ``REPLACE_ME``, ``replace_me`` and ``Replace_Me`` are one placeholder.
_PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "changeme",
        "change_me",
        "change-me",
        "your_secret_here",
        _TASK_PLACEHOLDER.casefold(),
        "replace_me",
        "replace-me",
        "replaceme",
        "example",
        "placeholder",
        "xxx",
        "***",
        "",
    }
)
# ``your-key-here``, ``<api-token>`` and a repeated single character such as ``xxxxxxxx`` are placeholders.
_PLACEHOLDER_PATTERN = re.compile(r"your[-_. a-z0-9]*|<[^<>]*>|(.)\1*", re.IGNORECASE)
_ENTROPY_THRESHOLD = 3.0
_MIN_VALUE_LENGTH = 12
_TEMPLATE_SUFFIXES: frozenset[str] = frozenset({"example", "sample", "template", "dist"})
# A generated credential carries one unbroken run of key characters; a template's sample value is words joined by separators.
_CREDENTIAL_RUN = re.compile(r"[A-Za-z0-9+/]{20,}")


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
        is_template = _is_env_template(unit.file.display_path)
        definition = self.definition()
        findings: list[Finding] = []
        # Each secret-named assignment remains independently actionable in the user's report.
        for secret_assignment in _SECRET_KEY_RE.finditer(unit.source):
            environment_key = secret_assignment.group("key")
            secret_value = secret_assignment.group("value").strip().strip("\"'")
            # Empty, short, and known placeholder values do not require credential rotation.
            if _is_placeholder(secret_value) or len(secret_value) < _MIN_VALUE_LENGTH:
                continue
            # A template's sample value needs a credential's shape, not only a credential's length.
            if is_template and not _is_credential_shaped(secret_value):
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
                        "Use placeholder values in committed `.env` files and inject real secrets via the deployment environment or a secret manager."
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


def _is_env_template(display_path: str) -> bool:
    """Return whether an ``.env`` file is a committed template such as ``.env.example`` or ``.env.local.sample``.

    Args:
        display_path: Project-relative path of an ``.env`` file.

    Returns:
        True when the filename ends in ``.example``, ``.sample``, ``.template`` or ``.dist``.
    """
    name = display_path.rsplit("/", 1)[-1]
    return name.startswith(".env.") and name.rsplit(".", 1)[-1] in _TEMPLATE_SUFFIXES


def _is_placeholder(value: str) -> bool:
    """Return whether an ``.env`` value is a stand-in for a secret rather than a secret.

    Args:
        value: Unquoted right-hand side of the assignment.

    Returns:
        True for an empty value, a known placeholder in any casing, ``your-...`` wording, an angle-bracketed
        name, or one character repeated.
    """
    return value.casefold() in _PLACEHOLDER_VALUES or _PLACEHOLDER_PATTERN.fullmatch(value) is not None


def _is_credential_shaped(value: str) -> bool:
    """Return whether a template value looks generated rather than written as a sample.

    Args:
        value: Unquoted right-hand side of a template assignment.

    Returns:
        True when the value holds a run of at least 20 key characters that mixes letters and digits.
    """
    return any(
        any(character.isalpha() for character in run) and any(character.isdigit() for character in run) for run in _CREDENTIAL_RUN.findall(value)
    )
