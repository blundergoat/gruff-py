"""Per-rule configuration overrides (enabled flag, thresholds, free-form options)."""

from dataclasses import dataclass, field
from typing import Any

from gruffpy.finding.severity import Severity


@dataclass(frozen=True, slots=True)
class SeverityThreshold:
    """Single-threshold override pairing one value with one severity.

    Set on a ``RuleSettings`` when the user picks the single-threshold
    shape (``threshold: X, severity: Y``) instead of the two-tier
    ``warning``/``error`` pair. When present it short-circuits the
    threshold matchers.
    """

    threshold: int | float
    severity: Severity


@dataclass(frozen=True, slots=True)
class ThresholdMatch:
    """Result of a threshold check - the value that fired and the matched severity."""

    threshold: int | float
    severity: Severity


@dataclass(frozen=True, slots=True)
class RuleSettings:
    """Resolved per-rule configuration.

    Attributes:
        enabled: Whether the rule should run.
        thresholds: Named numeric thresholds for the rule.
        options: Free-form rule options.
        severity_threshold: Optional single threshold and severity override.
    """

    enabled: bool = True
    thresholds: dict[str, int | float] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    severity_threshold: SeverityThreshold | None = None

    def numeric_threshold(self, name: str) -> int | float:
        """Return the threshold value for *name*, raising if missing or non-numeric.

        Booleans are rejected because bool subclasses int and would otherwise pass the numeric type check.

        Args:
            name: Threshold key (e.g. ``"warning"``, ``"maxAssertions"``).

        Returns:
            Numeric threshold value.

        Raises:
            LookupError: When the key is missing or its value is not numeric.
        """
        value = self.thresholds.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise LookupError(f'Missing numeric threshold "{name}".')
        return value

    def high_value_threshold_match(self, value: int | float) -> ThresholdMatch | None:
        """Match *value* against high-side thresholds (fires when value exceeds them).

        Only the configured severity threshold is checked; absent configuration yields no match.

        Args:
            value: Measured metric value (lines, complexity, etc.).

        Returns:
            The configured threshold and severity when value exceeds it, or None when no rubric is set or its threshold is not exceeded.
        """
        if self.severity_threshold is None or value <= self.severity_threshold.threshold:
            return None
        return ThresholdMatch(
            self.severity_threshold.threshold,
            self.severity_threshold.severity,
        )

    def low_value_threshold_match(self, value: int | float) -> ThresholdMatch | None:
        """Match *value* against low-side thresholds (fires when value falls below them).

        Mirror of high_value_threshold_match for metrics like maintainability index where smaller numbers are worse.

        Args:
            value: Measured metric value.

        Returns:
            A ThresholdMatch when value is below the configured threshold; None when no threshold is set or value is not below it.
        """
        if self.severity_threshold is None or value >= self.severity_threshold.threshold:
            return None
        return ThresholdMatch(
            self.severity_threshold.threshold,
            self.severity_threshold.severity,
        )

    def has_option(self, name: str) -> bool:
        """Return whether the resolved options contain the requested key.

        Args:
            name: Key to look up in the resolved options.

        Returns:
            True when the key is present, including keys supplied by registered defaults.
        """
        return name in self.options

    def option(self, name: str) -> Any:
        """Return the raw option value for *name*, raising if absent.

        Use :meth:`has_option` first when the caller wants a soft check.

        Args:
            name: Option key.

        Returns:
            Configured option value as-is.

        Raises:
            LookupError: When the option key is not present.
        """
        if name not in self.options:
            raise LookupError(f'Missing option "{name}".')
        return self.options[name]

    def string_list_option(self, name: str) -> list[str]:
        """Return *name* as a list-of-strings, validating element types.

        An absent option returns an empty list; a present value must be a list containing only strings.

        Args:
            name: Option key.

        Returns:
            Fresh list copy containing only strings.

        Raises:
            TypeError: When the option is set but is not a ``list[str]``.
        """
        value = self.options.get(name, [])
        if not isinstance(value, list):
            raise TypeError(f'Option "{name}" must be a list of strings.')
        for item in value:
            if not isinstance(item, str):
                raise TypeError(f'Option "{name}" must contain only strings.')
        return list(value)
