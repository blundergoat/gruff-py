from dataclasses import dataclass

from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.severity import Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.ADVISORY: 1,
    Severity.WARNING: 2,
    Severity.ERROR: 3,
}


@dataclass(frozen=True, slots=True)
class FindingDisplayFilter:
    min_severity: Severity | None = None
    include_pillars: tuple[Pillar, ...] = ()
    exclude_pillars: tuple[Pillar, ...] = ()
    include_rules: tuple[str, ...] = ()
    exclude_rules: tuple[str, ...] = ()

    def apply(self, findings: list[Finding] | tuple[Finding, ...]) -> list[Finding]:
        return [finding for finding in findings if self.allows(finding)]

    def is_active(self) -> bool:
        return (
            self.min_severity is not None
            or bool(self.include_pillars)
            or bool(self.exclude_pillars)
            or bool(self.include_rules)
            or bool(self.exclude_rules)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "active": self.is_active(),
            "minSeverity": self.min_severity.value if self.min_severity is not None else None,
            "includePillars": [pillar.value for pillar in self.include_pillars],
            "excludePillars": [pillar.value for pillar in self.exclude_pillars],
            "includeRules": list(self.include_rules),
            "excludeRules": list(self.exclude_rules),
        }

    def allows(self, finding: Finding) -> bool:
        if (
            self.min_severity is not None
            and _SEVERITY_RANK[finding.severity] < _SEVERITY_RANK[self.min_severity]
        ):
            return False
        if self.include_pillars and finding.pillar not in self.include_pillars:
            return False
        if finding.pillar in self.exclude_pillars:
            return False
        if self.include_rules and finding.rule_id not in self.include_rules:
            return False
        return finding.rule_id not in self.exclude_rules
