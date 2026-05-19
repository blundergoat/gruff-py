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
    """Result of a threshold check — the value that fired and the matched severity."""

    threshold: int | float
    severity: Severity


@dataclass(frozen=True, slots=True)
class RuleSettings:
    """Resolved per-rule configuration: enabled flag, thresholds, options, optional override."""

    enabled: bool = True
    thresholds: dict[str, int | float] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    severity_threshold: SeverityThreshold | None = None

    def numeric_threshold(self, name: str) -> int | float:
        """Return the threshold value for *name*, raising if missing or non-numeric.

        Booleans are rejected explicitly because ``bool`` is a subclass of
        ``int`` in Python and would otherwise pass the type check.

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

        If a single ``severity_threshold`` override is set, only that pair
        is checked. Otherwise compares against ``warning`` then ``error``
        keys, escalating to ``Severity.ERROR`` when the error threshold is
        passed.

        Args:
            value: Measured metric value (lines, complexity, etc.).

        Returns:
            Matching ``ThresholdMatch`` when *value* is over a threshold,
            else ``None``.
        """
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
        """Match *value* against low-side thresholds (fires when value falls below them).

        Mirror of :meth:`high_value_threshold_match` used by metrics like
        maintainability index where smaller numbers are worse.

        Args:
            value: Measured metric value.

        Returns:
            Matching ``ThresholdMatch`` when *value* is under a threshold,
            else ``None``.
        """
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
        """Return whether the option *name* was set (distinct from defaulting).

        Args:
            name: Option key.

        Returns:
            True when the option was explicitly configured.
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

        Defaults to an empty list when *name* is absent. Raises
        ``TypeError`` if the option is set but not a ``list[str]`` — a
        config error worth surfacing loudly.

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
