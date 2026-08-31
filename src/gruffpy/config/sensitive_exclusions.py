"""Parse and validate the ``sensitiveExclusions`` entries that may hide sensitive-data findings.

``FAMILY-CONTRACT.md`` (search: ``### 13a. Sensitive exclusions``) makes this section the only
channel that suppresses a sensitive-data finding, and keeps it separate from ``selection`` so the
ban on value matching is structural rather than a conditional a later edit can drop. Every problem
here is fatal: a suppression nobody can review is worse for the user than the finding it hides.

The parser never sees a finding, so an entry can only name a rule, a path, and a symbol the user
wrote down. Message and value keys are rejected by name.
"""

import re
from dataclasses import dataclass
from typing import Any

from gruffpy.config.exceptions import ConfigError
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier

SENSITIVE_EXCLUSIONS_KEY = "sensitiveExclusions"
"""Top-level config key owning every sensitive-data suppression a user can write."""

VALID_SENSITIVE_EXCLUSION_KEYS = frozenset({"rule", "path", "symbol", "reason"})
"""The complete accepted key set; ``message_contains``, ``value``, and ``preview`` are absent."""

_RULE_METACHARACTERS = "*?[]{}()|^$+\\"
_PATH_GLOB_METACHARACTERS = "*?[]{}"
_SELECTOR_VALUES = frozenset(pillar.value for pillar in Pillar) | frozenset(tier.value for tier in RuleTier)
_WINDOWS_DRIVE_PATTERN = re.compile(r"^[A-Za-z]:/")


@dataclass(frozen=True, slots=True)
class SensitiveExclusion:
    """One reviewed scope in which a single sensitive-data rule stays quiet.

    Immutable. ``index`` is the position the user wrote the entry at, and it appears in every
    diagnostic and in the audit row so a reader can map a count back to one config line.

    Attributes:
        index: Zero-based position of the entry in the user's ``sensitiveExclusions`` list.
        rule: Exactly one sensitive-data rule id.
        path: Project-relative display path, normalised the way findings report it.
        symbol: Optional qualified symbol that narrows the scope further.
        reason: Non-empty rationale a reviewer can judge without seeing the matched value.
    """

    index: int
    rule: str
    path: str
    symbol: str | None
    reason: str


def parse_sensitive_exclusions(
    section: Any,
    *,
    known_rule_ids: frozenset[str],
    sensitive_rule_ids: frozenset[str],
) -> tuple[SensitiveExclusion, ...]:
    """Validate every user entry before any sensitive-data finding can be hidden.

    Args:
        section: Raw ``sensitiveExclusions`` value from YAML or TOML; must be a list.
        known_rule_ids: Every registered rule id, used to reject typos.
        sensitive_rule_ids: Registered ids inside the sensitive-data pillar.

    Returns:
        Entries in the order the user wrote them; empty when the list is empty.

    Raises:
        ConfigError: When any entry is malformed, over-broad, unreviewable, or duplicated.
            The message names the entry index and the offending key.
    """
    if not isinstance(section, list):
        raise ConfigError(f'Config key "{SENSITIVE_EXCLUSIONS_KEY}" must be a list of entries.')
    exclusions: list[SensitiveExclusion] = []
    claimed_scopes: dict[tuple[str, str, str | None], int] = {}
    # Entries are checked in user order so the first reported index is the first one to fix.
    for index, entry in enumerate(section):
        exclusion = _parse_entry(
            index,
            entry,
            known_rule_ids=known_rule_ids,
            sensitive_rule_ids=sensitive_rule_ids,
        )
        scope = (exclusion.rule, exclusion.path, exclusion.symbol)
        first_index = claimed_scopes.get(scope)
        # Two entries claiming one scope would split the audit count arbitrarily.
        if first_index is not None:
            raise ConfigError(
                f'Config key "{SENSITIVE_EXCLUSIONS_KEY}[{index}]" is a duplicate scope of '
                f'"{SENSITIVE_EXCLUSIONS_KEY}[{first_index}]" (same rule, path, and symbol); '
                "merge them into one entry so the suppressed count belongs to one rationale."
            )
        claimed_scopes[scope] = index
        exclusions.append(exclusion)
    return tuple(exclusions)


def _parse_entry(
    index: int,
    entry: Any,
    *,
    known_rule_ids: frozenset[str],
    sensitive_rule_ids: frozenset[str],
) -> SensitiveExclusion:
    """Build one validated entry, rejecting every key the contract does not accept."""
    entry_path = f"{SENSITIVE_EXCLUSIONS_KEY}[{index}]"
    if not isinstance(entry, dict):
        raise ConfigError(f'Config key "{entry_path}" must be a table with "rule", "path", and "reason" keys.')
    _reject_unaccepted_keys(entry_path, entry)
    return SensitiveExclusion(
        index=index,
        rule=_parse_rule(entry_path, entry, known_rule_ids, sensitive_rule_ids),
        path=_parse_path(entry_path, entry),
        symbol=_parse_symbol(entry_path, entry),
        reason=_parse_reason(entry_path, entry),
    )


def _reject_unaccepted_keys(entry_path: str, entry: dict[Any, Any]) -> None:
    """Stop the scan when an entry carries a key outside the accepted four."""
    unaccepted = sorted(str(key) for key in entry if key not in VALID_SENSITIVE_EXCLUSION_KEYS)
    if not unaccepted:
        return
    raise ConfigError(
        f'Unknown keys in "{entry_path}": {unaccepted}. '
        f"Accepted keys: {sorted(VALID_SENSITIVE_EXCLUSION_KEYS)}. "
        "A sensitive exclusion matches on rule, path, and symbol only; message and value keys "
        "would reintroduce value-based suppression."
    )


def _parse_rule(
    entry_path: str,
    entry: dict[Any, Any],
    known_rule_ids: frozenset[str],
    sensitive_rule_ids: frozenset[str],
) -> str:
    """Resolve the one exact sensitive-data rule id the entry may silence."""
    rule = _required_string(f"{entry_path}.rule", entry, "rule")
    # A wildcard or expression would hide findings the user never enumerated.
    if any(character in rule for character in _RULE_METACHARACTERS):
        raise ConfigError(
            f'Config key "{entry_path}.rule" must be one exact rule id; {rule!r} contains a wildcard, glob, or regular-expression metacharacter.'
        )
    # A pillar or tier name is a group selector wearing a rule id.
    if rule in _SELECTOR_VALUES:
        raise ConfigError(f'Config key "{entry_path}.rule" must be one exact rule id, not the selector {rule!r}.')
    # A typo must fail loudly instead of silently suppressing nothing.
    if rule not in known_rule_ids:
        raise ConfigError(f'Config key "{entry_path}.rule" names unknown rule id {rule!r}.')
    if rule not in sensitive_rule_ids:
        raise ConfigError(
            f'Config key "{entry_path}.rule" names {rule!r}, which is outside the sensitive-data '
            f"pillar; {SENSITIVE_EXCLUSIONS_KEY} governs that pillar only."
        )
    return rule


def _parse_path(entry_path: str, entry: dict[Any, Any]) -> str:
    """Resolve the one project-relative file the entry may silence the rule in."""
    path = _normalise_report_path(_required_string(f"{entry_path}.path", entry, "path"))
    # An absolute path leaks the author's machine layout and escapes the project.
    if path.startswith("/") or _WINDOWS_DRIVE_PATTERN.match(path):
        raise ConfigError(f'Config key "{entry_path}.path" must be project-relative; {path!r} is absolute.')
    if ".." in path.split("/"):
        raise ConfigError(f'Config key "{entry_path}.path" must stay inside the project; {path!r} traverses out of it.')
    # A glob would claim files nobody enumerated, which is a blanket suppression.
    if any(character in path for character in _PATH_GLOB_METACHARACTERS):
        raise ConfigError(f'Config key "{entry_path}.path" must be one exact path; {path!r} contains a glob metacharacter.')
    return path


def _parse_symbol(entry_path: str, entry: dict[Any, Any]) -> str | None:
    """Resolve the optional symbol that narrows the entry beyond rule and path."""
    if "symbol" not in entry:
        return None
    return _required_string(f"{entry_path}.symbol", entry, "symbol")


def _parse_reason(entry_path: str, entry: dict[Any, Any]) -> str:
    """Require the rationale a reviewer needs to judge the suppression."""
    reason = entry.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ConfigError(
            f'Config key "{entry_path}.reason" must be a non-empty rationale; a suppression nobody can review is worse than the finding it hides.'
        )
    return reason


def _required_string(key_path: str, entry: dict[Any, Any], key: str) -> str:
    """Return a required non-empty string value, naming the exact key the user must fix."""
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise ConfigError(f'Config key "{key_path}" must be a non-empty string.')
    return value


def _normalise_report_path(path: str) -> str:
    """Match the project-relative display path findings already carry.

    Findings report forward-slash paths relative to the project root, so a caller's working
    directory cannot change whether an entry matches.

    Args:
        path: Path exactly as the user wrote it.

    Returns:
        The same path with Windows separators and a leading ``./`` removed.
    """
    normalised = path.replace("\\", "/")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised
