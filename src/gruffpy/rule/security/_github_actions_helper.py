"""Shared helpers for the ``security.github-actions-*`` workflow rules.

The workflow-file gate lives here so every GitHub Actions rule agrees on which
files are workflows; the rules then scan ``unit.source`` as raw text (these
files are delivered as ``SourceTextRule`` units with ``tree=None``).
"""

import re

_ON_KEY_RE = re.compile(r"""^["']?on["']?\s*:\s*(.*)$""")
_EVENT_KEY_RE = re.compile(r"""^(?:-\s*)?["']?([A-Za-z_]+)["']?\s*(?::|$)""")


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
    """Return the 1-based line number of *offset* within *source*.

    Args:
        source: Full source text being scanned.
        offset: Zero-based character offset of a match.

    Returns:
        One-based line number containing *offset*.
    """
    return source.count("\n", 0, offset) + 1


def declared_workflow_events(source: str) -> set[str]:
    """Return the events a workflow's top-level ``on:`` key declares.

    Reads the scalar, ``[a, b]`` flow-sequence, ``{a: x}`` flow-mapping, block-mapping and block-sequence forms. An
    ``if:`` expression or a step input that names an event elsewhere is not a trigger.

    Args:
        source: Full workflow text.

    Returns:
        The declared event names.
    """
    events: set[str] = set()
    in_on_block = False
    event_indent: int | None = None
    for raw in source.splitlines():
        code = raw.split(" #", 1)[0].rstrip()
        stripped = code.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(code) - len(code.lstrip(" "))
        if indent == 0:
            on_key = _ON_KEY_RE.match(stripped)
            value = on_key.group(1).strip() if on_key else ""
            in_on_block = on_key is not None and value == ""
            event_indent = None
            if on_key and value:
                for item in value.lstrip("[{").rstrip("]}").split(","):
                    event = item.split(":", 1)[0].strip().strip("\"'")
                    if event:
                        events.add(event)
            continue
        if not in_on_block:
            continue
        # The first nested line fixes the event level; deeper lines configure one event, such as its branches.
        if event_indent is None:
            event_indent = indent
        if indent == event_indent:
            match = _EVENT_KEY_RE.match(stripped)
            if match:
                events.add(match.group(1))
    return events
