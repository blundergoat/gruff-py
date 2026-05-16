"""Minimum severity that triggers a non-zero CLI exit, controlled by ``--fail-on``."""

from enum import StrEnum

from gruff.finding.severity import Severity


class FailThreshold(StrEnum):
    NONE = "none"
    ADVISORY = "advisory"
    WARNING = "warning"
    ERROR = "error"

    @classmethod
    def from_input(cls, value: str) -> "FailThreshold | None":
        try:
            return cls(value)
        except ValueError:
            return None

    def is_triggered_by(self, severity: Severity) -> bool:
        if self is FailThreshold.NONE:
            return False
        if self is FailThreshold.ADVISORY:
            return True
        if self is FailThreshold.WARNING:
            return severity in (Severity.WARNING, Severity.ERROR)
        return severity is Severity.ERROR
