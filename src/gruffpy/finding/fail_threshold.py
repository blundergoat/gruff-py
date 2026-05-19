"""Minimum severity that triggers a non-zero CLI exit, controlled by ``--fail-on``."""

from enum import StrEnum

from gruffpy.finding.severity import Severity


class FailThreshold(StrEnum):
    NONE = "none"
    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"

    @classmethod
    def from_input(cls, value: str) -> "FailThreshold | None":
        """Parse a user-supplied string into a threshold, returning ``None`` on miss.

        Used for ``--fail-on`` validation where invalid input should fall
        back to a default rather than crash.

        Args:
            value: Raw CLI string.

        Returns:
            Matching enum member, or ``None`` when *value* is not a known name.
        """
        try:
            return cls(value)
        except ValueError:
            return None

    def is_triggered_by(self, severity: Severity) -> bool:
        """Return whether *severity* meets or exceeds this fail threshold.

        ``NONE`` never triggers; ``ADVISORY`` triggers on anything;
        ``WARNING`` on warning or error; ``ERROR`` only on error.

        Args:
            severity: Finding severity to test.

        Returns:
            True when the run should exit non-zero because of this finding.
        """
        if self is FailThreshold.NONE:
            return False
        if self is FailThreshold.ADVISORY:
            return True
        if self is FailThreshold.WARNING:
            return severity in (Severity.WARNING, Severity.ERROR)
        return severity is Severity.ERROR
