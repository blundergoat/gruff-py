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

        Mirrors :meth:`FailThreshold.from_input` so CLI validation has a
        uniform shape across enums.

        Args:
            value: Raw CLI string.

        Returns:
            Matching enum member, or ``None`` when *value* is not a known format.
        """
        try:
            return cls(value)
        except ValueError:
            return None
