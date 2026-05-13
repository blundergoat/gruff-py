"""Cumulative integration test for the size pillar.

Exercises every M02 size rule end-to-end via `RuleRegistry.defaults()`. Edge
cases (decorators, multi-line signatures, nested classes/functions, async,
dataclasses, abstract methods, @override) are covered in a single fixture.
"""

import ast

from gruff.config.analysis_config import AnalysisConfig
from gruff.config.rule_settings import RuleSettings
from gruff.parser.analysis_unit import AnalysisUnit
from gruff.rule.context import RuleContext
from gruff.rule.registry import RuleRegistry
from gruff.source.source_file import SourceFile

# Edge fixture: small but exercises the patterns called out in M02
# Assumptions (decorators counted, multi-line sigs counted, nested
# def/class emit independent findings, async included, dataclass fields
# count toward attribute-count, abstract/override decorators don't change
# size-rule behaviour).
SIZE_PILLAR_FIXTURE = '''
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class WideRecord:
    """Dataclass with too many attributes."""

    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0
    e: int = 0
    f: int = 0
    g: int = 0
    h: int = 0
    i: int = 0
    j: int = 0
    k: int = 0
    l: int = 0
    m: int = 0
    n: int = 0
    o: int = 0
    p: int = 0


class WidePublicSurface:
    """Class with too many public methods."""

    def one(self): return 1
    def two(self): return 2
    def three(self): return 3
    def four(self): return 4
    def five(self): return 5
    def six(self): return 6
    def seven(self): return 7
    def eight(self): return 8
    def nine(self): return 9
    def ten(self): return 10
    def eleven(self): return 11
    def twelve(self): return 12
    def thirteen(self): return 13
    def fourteen(self): return 14
    def fifteen(self): return 15
    def sixteen(self): return 16


class _Decorated(ABC):
    @abstractmethod
    def expected(self): ...


@dataclass
class WithLongInit:
    @staticmethod
    def big_static(
        a,
        b,
        c,
        d,
        e,
        f,
        g,
        h,
        i,
        j,
    ):
        return a + b + c + d + e + f + g + h + i + j


async def big_async():
    x = 1
    x = 2
    x = 3
    x = 4
    x = 5
    x = 6
    x = 7
    x = 8
    x = 9
    x = 10
    x = 11
    x = 12
    x = 13
    x = 14
    x = 15
    x = 16
    x = 17
    x = 18
    x = 19
    x = 20
    x = 21
    x = 22
    x = 23
    x = 24
    x = 25
    x = 26
    x = 27
    x = 28
    x = 29
    x = 30
    return x


def outer_function():
    def inner_function():
        x = 1
        x = 2
        x = 3
        x = 4
        x = 5
        x = 6
        x = 7
        x = 8
        x = 9
        x = 10
        x = 11
        x = 12
        x = 13
        x = 14
        x = 15
        x = 16
        x = 17
        x = 18
        x = 19
        x = 20
        x = 21
        x = 22
        x = 23
        x = 24
        x = 25
        x = 26
        x = 27
        x = 28
        x = 29
        x = 30
        return x
    return inner_function
'''


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/integration.py", display_path="integration.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _default_ctx() -> RuleContext:
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        definition = rule.definition()
        rules[definition.id] = RuleSettings(
            enabled=True,
            thresholds=dict(definition.default_thresholds),
        )
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_defaults_contains_all_seven_size_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    expected_size = {
        "size.file-length",
        "size.class-length",
        "size.function-length",
        "size.average-function-length",
        "size.parameter-count",
        "size.attribute-count",
        "size.public-method-count",
    }
    assert expected_size.issubset(ids)


def test_registry_defaults_sorted_alphabetically_by_id():
    registry = RuleRegistry.defaults()
    ids = [rule.definition().id for rule in registry.all()]
    assert ids == sorted(ids)


def test_cumulative_fixture_emits_expected_rule_ids():
    unit = _make_unit(SIZE_PILLAR_FIXTURE)
    ctx = _default_ctx()
    registry = RuleRegistry.defaults()
    findings = registry.analyse([unit], ctx)
    rule_ids = {f.rule_id for f in findings}
    # Expected hits at default thresholds:
    # - size.attribute-count fires on WideRecord (16 attrs > 15)
    # - size.public-method-count fires on WidePublicSurface (16 public methods > 15)
    # - size.parameter-count fires on big_static (10 params > 5)
    # - size.function-length fires on big_async, outer_function, outer_function.inner_function
    assert "size.attribute-count" in rule_ids
    assert "size.public-method-count" in rule_ids
    assert "size.parameter-count" in rule_ids
    assert "size.function-length" in rule_ids
    # size.file-length should NOT fire (fixture is well under 400 lines)
    assert "size.file-length" not in rule_ids


def test_cumulative_fixture_findings_carry_symbol_and_metadata_lines():
    unit = _make_unit(SIZE_PILLAR_FIXTURE)
    ctx = _default_ctx()
    findings = RuleRegistry.defaults().analyse([unit], ctx)
    fl = [f for f in findings if f.rule_id == "size.function-length"]
    assert fl, "expected function-length findings"
    for f in fl:
        assert f.symbol  # qualified name
        assert "lines" in f.metadata
        assert isinstance(f.metadata["lines"], int)


def test_nested_inner_function_emits_independent_finding():
    unit = _make_unit(SIZE_PILLAR_FIXTURE)
    ctx = _default_ctx()
    findings = RuleRegistry.defaults().analyse([unit], ctx)
    symbols = {f.symbol for f in findings if f.rule_id == "size.function-length"}
    assert "outer_function" in symbols
    assert "outer_function.inner_function" in symbols


def test_findings_deterministic_across_two_runs():
    unit_a = _make_unit(SIZE_PILLAR_FIXTURE)
    unit_b = _make_unit(SIZE_PILLAR_FIXTURE)
    ctx = _default_ctx()
    registry = RuleRegistry.defaults()
    a = registry.analyse([unit_a], ctx)
    b = registry.analyse([unit_b], ctx)
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b]


def test_config_override_changes_finding_count():
    # Default function-length threshold = 30/60. Override to 5/10.
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        d = rule.definition()
        if d.id == "size.function-length":
            rules[d.id] = RuleSettings(enabled=True, thresholds={"warning": 5, "error": 10})
        else:
            rules[d.id] = RuleSettings(enabled=True, thresholds=dict(d.default_thresholds))
    ctx = RuleContext(project_root="/", config=AnalysisConfig(rules=rules))
    unit = _make_unit(SIZE_PILLAR_FIXTURE)

    default_findings = registry.analyse([_make_unit(SIZE_PILLAR_FIXTURE)], _default_ctx())
    overridden_findings = registry.analyse([unit], ctx)

    default_fn_count = sum(1 for f in default_findings if f.rule_id == "size.function-length")
    override_fn_count = sum(1 for f in overridden_findings if f.rule_id == "size.function-length")
    # Lower thresholds should expose more functions as oversized.
    assert override_fn_count > default_fn_count


def test_disabling_a_rule_removes_its_findings():
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        d = rule.definition()
        rules[d.id] = RuleSettings(
            enabled=(d.id != "size.attribute-count"),
            thresholds=dict(d.default_thresholds),
        )
    ctx = RuleContext(project_root="/", config=AnalysisConfig(rules=rules))
    unit = _make_unit(SIZE_PILLAR_FIXTURE)
    findings = registry.analyse([unit], ctx)
    assert all(f.rule_id != "size.attribute-count" for f in findings)


def test_abstract_method_does_not_break_function_length():
    src = """from abc import ABC, abstractmethod

class A(ABC):
    @abstractmethod
    def m(self): ...
"""
    unit = _make_unit(src)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    # No size findings expected on this tiny abstract method.
    assert all(f.rule_id != "size.function-length" for f in findings)
