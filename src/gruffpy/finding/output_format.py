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
        try:
            return cls(value)
        except ValueError:
            return None
