from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.scoring.composite_finding_factory import CompositeFindingFactory


def _f(
    rule_id: str,
    *,
    file_path: str = "x.py",
    symbol: str | None = "foo",
    pillar: Pillar,
    severity: Severity = Severity.WARNING,
    line: int | None = 1,
    end_line: int | None = 10,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} hit",
        file_path=file_path,
        line=line,
        severity=severity,
        pillar=pillar,
        tier=RuleTier.V01,
        confidence=Confidence.HIGH,
        end_line=end_line,
        symbol=symbol,
    )


def test_no_composite_when_only_size_findings():
    findings = [_f("size.function-length", pillar=Pillar.SIZE)]
    out = CompositeFindingFactory().synthesise(findings)
    assert len(out) == 1
    assert out[0].rule_id == "size.function-length"


def test_no_composite_when_only_complexity_findings():
    findings = [_f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY)]
    out = CompositeFindingFactory().synthesise(findings)
    assert len(out) == 1


def test_composite_fires_on_size_complexity_overlap():
    findings = [
        _f("size.function-length", pillar=Pillar.SIZE, line=5, end_line=50),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, line=5, end_line=50),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    composites = [f for f in out if f.rule_id == "design.god-method"]
    assert len(composites) == 1
    c = composites[0]
    assert c.symbol == "foo"
    assert c.pillar == Pillar.DESIGN
    assert set(c.secondary_pillars) == {Pillar.COMPLEXITY, Pillar.SIZE}
    assert c.metadata["componentRules"] == [
        "complexity.cyclomatic",
        "size.function-length",
    ]


def test_composite_uses_min_line_max_endline():
    findings = [
        _f("size.function-length", pillar=Pillar.SIZE, line=10, end_line=50),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, line=5, end_line=40),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    composite = next(f for f in out if f.rule_id == "design.god-method")
    assert composite.line == 5
    assert composite.end_line == 50


def test_composite_severity_is_worst_of_contributors():
    findings = [
        _f("size.function-length", pillar=Pillar.SIZE, severity=Severity.WARNING),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, severity=Severity.ERROR),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    composite = next(f for f in out if f.rule_id == "design.god-method")
    assert composite.severity == Severity.ERROR


def test_composite_component_rules_sorted_and_distinct():
    findings = [
        _f("complexity.npath", pillar=Pillar.COMPLEXITY),
        _f("size.function-length", pillar=Pillar.SIZE),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY),
        _f("size.parameter-count", pillar=Pillar.SIZE),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY),  # duplicate id
    ]
    out = CompositeFindingFactory().synthesise(findings)
    composite = next(f for f in out if f.rule_id == "design.god-method")
    assert composite.metadata["componentRules"] == [
        "complexity.cyclomatic",
        "complexity.npath",
        "size.function-length",
        "size.parameter-count",
    ]


def test_composite_does_not_fire_on_unrelated_pillars():
    # naming + docs co-occur on the same symbol — no composite.
    findings = [
        _f("naming.confusing-name", pillar=Pillar.NAMING),
        _f("docs.missing-function-docstring", pillar=Pillar.DOCUMENTATION),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    assert all(f.rule_id != "design.god-method" for f in out)


def test_findings_without_symbol_dont_contribute():
    findings = [
        _f("size.function-length", pillar=Pillar.SIZE, symbol=None),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol=None),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    assert all(f.rule_id != "design.god-method" for f in out)


def test_composite_fingerprint_uses_min_line_and_symbol():
    findings = [
        _f("size.function-length", pillar=Pillar.SIZE, line=5, end_line=50),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, line=5, end_line=50),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    composite = next(f for f in out if f.rule_id == "design.god-method")
    # fingerprint should be stable: same inputs across two factory runs
    out2 = CompositeFindingFactory().synthesise(findings)
    composite2 = next(f for f in out2 if f.rule_id == "design.god-method")
    assert composite.fingerprint() == composite2.fingerprint()
    assert len(composite.fingerprint()) == 16


def test_two_god_methods_on_different_symbols():
    findings = [
        _f("size.function-length", pillar=Pillar.SIZE, symbol="foo"),
        _f("complexity.cyclomatic", pillar=Pillar.COMPLEXITY, symbol="foo"),
        _f("size.parameter-count", pillar=Pillar.SIZE, symbol="bar"),
        _f("complexity.npath", pillar=Pillar.COMPLEXITY, symbol="bar"),
    ]
    out = CompositeFindingFactory().synthesise(findings)
    composites = [f for f in out if f.rule_id == "design.god-method"]
    symbols = {c.symbol for c in composites}
    assert symbols == {"foo", "bar"}
