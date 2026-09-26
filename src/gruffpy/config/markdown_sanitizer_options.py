"""Validate the Markdown sanitizer names users place in rule configuration.

The loader calls this boundary before a scan starts, so malformed helper names
become clear config errors instead of unexplained findings. The Markdown rule
also reuses it when tests or API callers construct settings without the loader.
"""

import keyword
from typing import Any

from gruffpy.config.exceptions import ConfigError

MARKDOWN_SANITIZER_RULE_ID = "security.unsanitized-markdown-interpolation"
LABEL_SANITIZERS_OPTION = "labelSanitizers"
URL_SANITIZERS_OPTION = "urlSanitizers"
MARKDOWN_SANITIZER_OPTION_NAMES = frozenset({LABEL_SANITIZERS_OPTION, URL_SANITIZERS_OPTION})
DEFAULT_LABEL_SANITIZERS: tuple[str, ...] = ()
DEFAULT_URL_SANITIZERS: tuple[str, ...] = (
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
)


def validate_markdown_sanitizer_targets(option_name: str, value: Any) -> list[str]:
    """Return exact call targets or stop the user's scan with a config error.

    Args:
        option_name: Public option key shown in the user's error message.
        value: Parsed configuration value; an empty list requests strict mode.

    Returns:
        Fresh target list; empty means the user trusts no call for this slot.

    Raises:
        ConfigError: When a user supplies a scalar, empty name, wildcard, or
            non-Python target such as ``helpers.*``.
    """
    public_config_key = f"rules.{MARKDOWN_SANITIZER_RULE_ID}.options.{option_name}"
    # A scalar or mapping cannot describe the user's ordered helper list.
    if not isinstance(value, list):
        raise ConfigError(f'Config key "{public_config_key}" must be a list of exact Python call targets.')
    validated_targets: list[str] = []
    # Each configured spelling must map to one callable the scanner can see.
    for configured_target in value:
        # Non-text entries cannot match a Python call shown in the user's source.
        if not isinstance(configured_target, str):
            raise ConfigError(
                f'Config key "{public_config_key}" contains invalid call target '
                f'{configured_target!r}; use a name such as "markdown_label" or '
                '"helpers.markdown_url".'
            )
        # Empty, wildcard, or syntactically invalid names would make trust ambiguous.
        if not _is_exact_python_call_target(configured_target):
            raise ConfigError(
                f'Config key "{public_config_key}" contains invalid call target '
                f'{configured_target!r}; use a name such as "markdown_label" or '
                '"helpers.markdown_url".'
            )
        validated_targets.append(configured_target)
    return validated_targets


def _is_exact_python_call_target(configured_target: str) -> bool:
    """Return whether text is a non-empty dotted Python identifier.

    Args:
        configured_target: User spelling; empty text means no callable was named.

    Returns:
        ``True`` only for exact lexical targets without wildcards or keywords.
    """
    # Blank text gives the scanner no user-visible call to match.
    if not configured_target:
        return False
    target_parts = configured_target.split(".")
    # Every dotted segment must be usable as source-level Python syntax.
    return all(target_part.isidentifier() and not keyword.iskeyword(target_part) for target_part in target_parts)
