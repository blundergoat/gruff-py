"""Shared helpers for the ``security.github-actions-*`` workflow rules.

The workflow-file gate lives here so every GitHub Actions rule agrees on which
files are workflows; the rules then scan ``unit.source`` as raw text (these
files are delivered as ``SourceTextRule`` units with ``tree=None``).
"""

import re

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

_ON_KEY = re.compile(r"""^["']?on["']?\s*:""")


def is_workflow_file(display_path: str) -> bool:
    """Return whether *display_path* is a GitHub Actions workflow YAML file.

    Args:
        display_path: Project-relative path stored on the analysis unit.

    Returns:
        True for ``.github/workflows/*.yml`` / ``*.yaml`` paths.
    """
    normalised = display_path.replace("\\", "/")
    return ".github/workflows/" in normalised and normalised.endswith((".yml", ".yaml"))


def source_line(source: str, offset: int) -> int:
    """Return the 1-based line number of offset within source.

    Args:
        source: Full source text being scanned.
        offset: Zero-based character offset of a match.

    Returns:
        One-based line number containing the offset.
    """
    return source.count("\n", 0, offset) + 1


def declared_workflow_events(source: str) -> set[str]:
    """Read the event names that can actually start the user's workflow.
    Accept scalar, flow and block forms of `on:`. A later YAML error still permits checks when the trigger itself is readable.
    The rules use these names so a job condition mentioning an event cannot be mistaken for a trigger.

    Args:
        source: Full workflow text.

    Returns:
        The declared event names.
    """
    try:
        document = yaml.compose(source, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError):
        # A malformed job can prevent parsing while the workflow still has a readable `on:` section worth checking.
        document = _recover_trigger_mapping(source)
    # An empty document or a top-level YAML list cannot declare GitHub Actions events.
    if not isinstance(document, MappingNode):
        return set()
    # YAML's resolved tag can be boolean for an unquoted on key; the scalar retains its spelling.
    return {event for key, value in document.value if isinstance(key, ScalarNode) and key.value == "on" for event in _event_names(value)}


def _recover_trigger_mapping(source: str) -> Node | None:
    """Try the top-level `on:` section when a later workflow section prevents parsing.
    A readable trigger still lets the security rules identify jobs a reviewer needs to examine.

    Args:
        source: Workflow text that could not be composed as one YAML document.

    Returns:
        A node for a readable trigger section, or None when its own syntax cannot be parsed.
    """
    trigger_lines: list[str] = []
    # Collect the trigger section by indentation so a nested `on:` in a job cannot start this recovery path.
    for line in source.split("\n"):
        # Begin collecting only at a top-level trigger key.
        if _ON_KEY.match(line):
            trigger_lines.append(line)
        # An indented value or indentationless list item can still belong to `on:`.
        elif trigger_lines:
            # A new top-level section such as `jobs:` ends the trigger the rules need.
            if line and not line.startswith((" ", "\t", "#", "- ")):
                break
            trigger_lines.append(line)
    try:
        document: Node | None = yaml.compose("\n".join(trigger_lines), Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError):
        # If the trigger has a broken list such as an unclosed `[push`, it cannot justify any event-dependent finding.
        return None
    return document


def _event_names(value: Node) -> set[str]:
    """Read the event names without treating settings under an event as additional triggers.
    Use this for the string, list or mapping forms GitHub Actions accepts under `on:`.

    Args:
        value: The trigger scalar, sequence or mapping.

    Returns:
        Scalar event names, ignoring option values nested under an event.
    """
    # `on: push` declares one event, while a blank scalar supplies no event name.
    if isinstance(value, ScalarNode):
        return {value.value} if value.value else set()
    # A mapping contributes only event keys. A list contributes each event name directly.
    entries = (key for key, _ in value.value) if isinstance(value, MappingNode) else value.value if isinstance(value, SequenceNode) else ()
    return {entry.value for entry in entries if isinstance(entry, ScalarNode)}
