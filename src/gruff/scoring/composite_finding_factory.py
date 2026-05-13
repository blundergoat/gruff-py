"""Composite finding synthesis (ADR-003a).

Runs in ``cli.py`` after ``RuleRegistry.analyse()`` returns. Groups per-unit
findings by ``(file_path, symbol)``; when at least one Complexity finding and
one Size finding co-occur on the same symbol, emits a synthesised
``design.god-method`` finding.

Fingerprint inputs are locked by ADR-003a: ``rule_id``, ``file``, ``symbol``,
``line`` (min over contributors), ``end_line`` (max over contributors),
``column=None``. ``metadata.componentRules`` is a sorted tuple of contributor
rule IDs; ``secondary_pillars`` is the sorted distinct pillar set excluding
``design``.
"""

from collections import defaultdict

from gruff.finding.confidence import Confidence
from gruff.finding.finding import Finding
from gruff.finding.pillar import Pillar
from gruff.finding.rule_tier import RuleTier
from gruff.finding.severity import Severity

# Per the M03 plan: only these rules contribute to design.god-method.
_COMPLEXITY_CONTRIBUTORS = frozenset(
    {
        "complexity.cognitive",
        "complexity.cyclomatic",
        "complexity.nesting-depth",
        "complexity.npath",
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
        """
        result = list(findings)
        result.extend(self._god_methods(findings))
        return result

    def _god_methods(self, findings: list[Finding]) -> list[Finding]:
        # Group findings by (file_path, symbol). Skip findings without a symbol.
        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for f in findings:
            if f.symbol is None:
                continue
            if f.rule_id not in _COMPLEXITY_CONTRIBUTORS and f.rule_id not in _SIZE_CONTRIBUTORS:
                continue
            groups[(f.file_path, f.symbol)].append(f)

        composites: list[Finding] = []
        for (file_path, symbol), members in groups.items():
            complexity_hits = [m for m in members if m.rule_id in _COMPLEXITY_CONTRIBUTORS]
            size_hits = [m for m in members if m.rule_id in _SIZE_CONTRIBUTORS]
            if not (complexity_hits and size_hits):
                continue

            component_rules = tuple(sorted({m.rule_id for m in members}))
            secondary = tuple(sorted({m.pillar for m in members if m.pillar != Pillar.DESIGN}))
            line = min(m.line for m in members if m.line is not None)
            end_line_values = [m.end_line for m in members if m.end_line is not None]
            end_line = max(end_line_values) if end_line_values else None

            # Severity: take the worst (most severe) among contributors.
            severity = _worst_severity([m.severity for m in members])

            composites.append(
                Finding(
                    rule_id=self.GOD_METHOD_RULE_ID,
                    message=(
                        f"Symbol {symbol!r} is a god method: "
                        f"{len(component_rules)} overlapping size/complexity findings "
                        f"on {file_path}:{line}."
                    ),
                    file_path=file_path,
                    line=line,
                    severity=severity,
                    pillar=Pillar.DESIGN,
                    tier=RuleTier.V01,
                    confidence=Confidence.HIGH,
                    end_line=end_line,
                    column=None,
                    symbol=symbol,
                    remediation=(
                        "Split the symbol: each contributor metric flags a distinct smell "
                        "(too long, too complex, too deeply nested, too many parameters)."
                    ),
                    secondary_pillars=secondary,
                    metadata={
                        "componentRules": list(component_rules),
                        "contributorCount": len(component_rules),
                    },
                ),
            )
        return composites


def _worst_severity(severities: list[Severity]) -> Severity:
    order = (Severity.ADVISORY, Severity.WARNING, Severity.ERROR)
    worst = Severity.ADVISORY
    for s in severities:
        if order.index(s) > order.index(worst):
            worst = s
    return worst
