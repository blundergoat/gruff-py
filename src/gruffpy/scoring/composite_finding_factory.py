"""Composite finding synthesis (ADR-016).

Runs in ``cli.py`` after ``RuleRegistry.analyse()`` returns. Groups per-unit
findings by ``(file_path, symbol)``; when at least one Complexity finding and
one Size finding co-occur on the same symbol, emits a synthesised
``design.god-method`` finding.

Fingerprint inputs are locked by ADR-016: ``rule_id``, ``file``, ``symbol``,
``line`` (min over contributors), ``end_line`` (max over contributors),
``column=None``. ``metadata.componentRules`` is a sorted tuple of contributor
rule IDs; ``secondary_pillars`` is the sorted distinct pillar set excluding
``design``.
"""

from collections import defaultdict

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity

# Only these rules contribute to design.god-method.
_COMPLEXITY_CONTRIBUTORS = frozenset(
    {
        "complexity.cognitive",
        "complexity.cyclomatic",
        "complexity.nesting-depth",
    }
)
_SIZE_CONTRIBUTORS = frozenset(
    {
        "size.function-length",
        "size.parameter-count",
    }
)


class CompositeFindingFactory:
    """Synthesise composite findings (e.g. ``design.god-method``) from a
    per-unit finding list. Pure function in disguise: stateless; the class
    exists so a future composite-rule can compose with the same machinery.
    """

    GOD_METHOD_RULE_ID = "design.god-method"

    def synthesise(self, findings: list[Finding]) -> list[Finding]:
        """Return *findings* with any synthesised composite findings appended.

        Input order is preserved; composites are appended at the end. Callers
        that need sorted/deduplicated output should pipe the result back
        through their existing post-processing.

        Args:
            findings: Per-unit findings to inspect for composite contributors.

        Returns:
            New list: the originals plus any composite findings (e.g.
            ``design.god-method``) synthesised from contributor groups.
        """
        result = list(findings)
        result.extend(self._god_methods(findings))
        return result

    def _god_methods(self, findings: list[Finding]) -> list[Finding]:
        composites: list[Finding] = []
        for (file_path, symbol), members in _contributor_groups(findings).items():
            if not _has_complexity_and_size(members):
                continue
            composites.append(
                _god_method_finding(self.GOD_METHOD_RULE_ID, file_path, symbol, members)
            )
        return composites


def _contributor_groups(findings: list[Finding]) -> dict[tuple[str, str], list[Finding]]:
    groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.symbol is None or not _is_contributor(finding):
            continue
        groups[(finding.file_path, finding.symbol)].append(finding)
    return groups


def _is_contributor(finding: Finding) -> bool:
    return finding.rule_id in _COMPLEXITY_CONTRIBUTORS or finding.rule_id in _SIZE_CONTRIBUTORS


def _has_complexity_and_size(members: list[Finding]) -> bool:
    return _has_rule_from(members, _COMPLEXITY_CONTRIBUTORS) and _has_rule_from(
        members,
        _SIZE_CONTRIBUTORS,
    )


def _has_rule_from(members: list[Finding], contributor_ids: frozenset[str]) -> bool:
    return any(member.rule_id in contributor_ids for member in members)


def _god_method_finding(
    rule_id: str,
    file_path: str,
    symbol: str,
    members: list[Finding],
) -> Finding:
    component_rules = tuple(sorted({member.rule_id for member in members}))
    line = min(member.line for member in members if member.line is not None)
    return Finding(
        rule_id=rule_id,
        message=(
            f"Symbol {symbol!r} is a god method: "
            f"{len(component_rules)} overlapping size/complexity findings on {file_path}:{line}."
        ),
        file_path=file_path,
        line=line,
        severity=_worst_severity([member.severity for member in members]),
        pillar=Pillar.DESIGN,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        end_line=_max_end_line(members),
        column=None,
        symbol=symbol,
        remediation=(
            "Split the symbol: each contributor metric flags a distinct smell "
            "(too long, too complex, too deeply nested, too many parameters)."
        ),
        secondary_pillars=_secondary_pillars(members),
        metadata={
            "componentRules": list(component_rules),
            "contributorCount": len(component_rules),
        },
    )


def _max_end_line(members: list[Finding]) -> int | None:
    end_line_values = [member.end_line for member in members if member.end_line is not None]
    return max(end_line_values) if end_line_values else None


def _secondary_pillars(members: list[Finding]) -> tuple[Pillar, ...]:
    return tuple(sorted({member.pillar for member in members if member.pillar != Pillar.DESIGN}))


def _worst_severity(severities: list[Severity]) -> Severity:
    order = (Severity.ADVISORY, Severity.WARNING, Severity.ERROR)
    worst = Severity.ADVISORY
    for s in severities:
        if order.index(s) > order.index(worst):
            worst = s
    return worst
