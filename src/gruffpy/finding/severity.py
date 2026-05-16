"""Severity levels emitted by rules and reported by the CLI."""

from enum import StrEnum


class Severity(StrEnum):
    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"

    @classmethod
    def from_input(cls, value: str) -> "Severity | None":
        try:
            return cls(value)
        except ValueError:
            return None
