"""Shared helpers for the ``security.github-actions-*`` workflow rules.

The workflow-file gate lives here so every GitHub Actions rule agrees on which
files are workflows; the rules then scan ``unit.source`` as raw text (these
files are delivered as ``SourceTextRule`` units with ``tree=None``).
"""


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
