"""Reporter-side filter that applies ``--min-severity`` / pillar selection."""

from dataclasses import dataclass, replace

from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.severity import Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.ADVISORY: 1,
    Severity.WARNING: 2,
    Severity.ERROR: 3,
}


@dataclass(frozen=True, slots=True)
class FindingDisplayFilter:
    """Reporter-side filter for min-severity, pillar, and rule selectors.

    Attributes:
        min_severity: Minimum severity to include, if configured.
        include_pillars: Pillars that must be present when set.
        exclude_pillars: Pillars removed after includes are evaluated.
        include_rules: Rule ids that must be present when set.
        exclude_rules: Rule ids removed after includes are evaluated.
    """

    min_severity: Severity | None = None
    include_pillars: tuple[Pillar, ...] = ()
    exclude_pillars: tuple[Pillar, ...] = ()
    include_rules: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()

    def with_configured_floor(self, configured_floor: Severity | None) -> "FindingDisplayFilter":
        """Apply the configured severity floor unless this filter already has one.

        A command-line floor takes precedence over the project default.

        Args:
            configured_floor: Project minimumSeverity value, or None to keep this filter unchanged.

        Returns:
            This filter when a floor is already set or configured_floor is None; otherwise a copy with the configured floor.
        """
        if self.min_severity is not None or configured_floor is None:
            return self
        return replace(self, min_severity=configured_floor)

    def filter_findings(self, findings: list[Finding] | tuple[Finding, ...]) -> list[Finding]:
        """Return only the findings that satisfy every active selector.

        Args:
            findings: Findings produced by the analyser, in stable sort order.

        Returns:
            Subset preserving the original order.
        """
        return [finding for finding in findings if self.is_allowed(finding)]

    def is_active(self) -> bool:
        """Return whether any display selector is configured.

        Returns:
            True if at least one min-severity / pillar / rule selector is set.
        """
        return (
            self.min_severity is not None
            or bool(self.include_pillars)
            or bool(self.exclude_pillars)
            or bool(self.include_rules)
            or bool(self.exclude_rules)
        )

    def to_dict(self) -> dict[str, object]:
        """Serialise the filter shape for inclusion in JSON / SARIF report metadata.

        Enum members use their value strings so the output is JSON-native.

        Returns:
            Plain dict containing the filter configuration plus an active flag.
        """
        return {
            "active": self.is_active(),
            "minSeverity": self.min_severity.value if self.min_severity is not None else None,
            "includePillars": [pillar.value for pillar in self.include_pillars],
            "excludePillars": [pillar.value for pillar in self.exclude_pillars],
            "includeRules": list(self.include_rules),
            "excludeRules": list(self.exclude_rules),
        }

    def is_allowed(self, finding: Finding) -> bool:
        """Return whether *finding* passes every active selector.

        Selector order: min-severity gate, then pillar include/exclude,
        then rule include/exclude. Exclude always wins over include.

        Args:
            finding: One finding to test.

        Returns:
            True when the finding should appear in reports.
        """
        if self.min_severity is not None and _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[self.min_severity]:
            return False
        if self.include_pillars and finding.pillar not in self.include_pillars:
            return False
        if finding.pillar in self.exclude_pillars:
            return False
        if self.include_rules and finding.rule_id not in self.include_rules:
            return False
        return finding.rule_id not in self.exclude_rules
