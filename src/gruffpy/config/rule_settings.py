"""Per-rule configuration overrides (enabled flag, thresholds, free-form options)."""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.severity import Severity


@dataclass(frozen=True, slots=True)
class SeverityThreshold:
    threshold: int | float
    severity: Severity


@dataclass(frozen=True, slots=True)
class ThresholdMatch:
    threshold: int | float
    severity: Severity


@dataclass(frozen=True, slots=True)
class RuleSettings:
    enabled: bool = True
    thresholds: dict[str, int | float] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    severity_threshold: SeverityThreshold | None = None

    def numeric_threshold(self, name: str) -> int | float:
        value = self.thresholds.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise LookupError(f'Missing numeric threshold "{name}".')
        return value

    def high_value_threshold_match(self, value: int | float) -> ThresholdMatch | None:
        if self.severity_threshold is not None:
            if value <= self.severity_threshold.threshold:
                return None
            return ThresholdMatch(
                self.severity_threshold.threshold,
                self.severity_threshold.severity,
            )

        warning_threshold = self.numeric_threshold("warning")
        if value <= warning_threshold:
            return None

        error_threshold = self.numeric_threshold("error")
        severity = Severity.ERROR if value > error_threshold else Severity.WARNING
        threshold = error_threshold if severity is Severity.ERROR else warning_threshold
        return ThresholdMatch(threshold, severity)

    def low_value_threshold_match(self, value: int | float) -> ThresholdMatch | None:
        if self.severity_threshold is not None:
            if value >= self.severity_threshold.threshold:
                return None
            return ThresholdMatch(
                self.severity_threshold.threshold,
                self.severity_threshold.severity,
            )

        warning_threshold = self.numeric_threshold("warning")
        if value >= warning_threshold:
            return None

        error_threshold = self.numeric_threshold("error")
        severity = Severity.ERROR if value < error_threshold else Severity.WARNING
        threshold = error_threshold if severity is Severity.ERROR else warning_threshold
        return ThresholdMatch(threshold, severity)

    def has_option(self, name: str) -> bool:
        return name in self.options

    def option(self, name: str) -> Any:
        if name not in self.options:
            raise LookupError(f'Missing option "{name}".')
        return self.options[name]

    def string_list_option(self, name: str) -> list[str]:
        value = self.options.get(name, [])
        if not isinstance(value, list):
            raise TypeError(f'Option "{name}" must be a list of strings.')
        for item in value:
            if not isinstance(item, str):
                raise TypeError(f'Option "{name}" must contain only strings.')
        return list(value)
