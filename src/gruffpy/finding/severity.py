"""Severity levels emitted by rules and reported by the CLI."""

from enum import StrEnum


class Severity(StrEnum):
    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"

    @classmethod
    def from_input(cls, value: str) -> "Severity | None":
        """Parse a user-supplied severity string, returning ``None`` for unknown values.

        Used by config loaders to validate per-rule severity overrides
        without throwing on typos.

        Args:
            value: Raw string from CLI flags or config files.

        Returns:
            Matching enum member, or ``None`` when *value* is not a known severity.
        """
        try:
            return cls(value)
        except ValueError:
            return None
