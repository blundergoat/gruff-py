"""Supported output renderings for ``gruff-py analyse`` (text, json, html, ...)."""

from enum import StrEnum


class OutputFormat(StrEnum):
    TEXT = "text"
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"
    GITHUB = "github"
    HOTSPOT = "hotspot"
    SARIF = "sarif"

    @classmethod
    def from_input(cls, value: str) -> "OutputFormat | None":
        """Parse a user-supplied format string, returning ``None`` for unknown values.

        Args:
            value: Raw CLI string.

        Returns:
            Matching enum member, or None for an unknown format. The caller can use None to decide whether to report invalid input.
        """
        try:
            return cls(value)
        except ValueError:
            return None
