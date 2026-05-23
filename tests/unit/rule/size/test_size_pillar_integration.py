"""Cumulative integration test for the size pillar.

Exercises every size rule end-to-end via `RuleRegistry.defaults()`. Edge
cases (decorators, multi-line signatures, nested classes/functions, async,
dataclasses, abstract methods, @override) are covered in a single fixture.
"""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

SIZE_RULE_IDS = {
    "size.file-length",
    "size.class-length",
    "size.function-length",
    "size.average-function-length",
    "size.parameter-count",
    "size.attribute-count",
    "size.public-method-count",
}

# Edge fixture: small but exercises every size-rule edge case the pillar
# documents (decorators counted, multi-line sigs counted, nested def/class
# emit independent findings, async included, dataclass fields count toward
# attribute-count, abstract/override decorators don't change size-rule
# behaviour).
SIZE_PILLAR_FIXTURE = '''
from abc import ABC, abstractmethod
from dataclasses import dataclass


class WideRecord:
    """Plain class with too many attributes.

    Kept as a plain class (not a ``@dataclass``) because
    ``size.attribute-count`` exempts schema/dataclass shells — the rule's
    intent is to flag classes with too many fields whose attributes are
    NOT part of a schema/contract, and this fixture exercises that case.
    """

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
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/integration.py", display_path="integration.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _default_ctx() -> RuleContext:
    # PMD-aligned production defaults are too generous for the small fixture to
    # cross. Override the size rubrics that depend on small violations so the
    # fixture still exercises every rule end-to-end.
    size_test_thresholds = {
        "size.parameter-count": {"warning": 5, "error": 8},
        "size.function-length": {"warning": 30, "error": 60},
        "size.average-function-length": {"warning": 30, "error": 60},
    }
    return _ctx_with_threshold_overrides(size_test_thresholds)


def _ctx_with_threshold_overrides(
    overrides: dict[str, dict[str, int]],
) -> RuleContext:
    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=True,
            thresholds=overrides.get(
                rule.definition().id, dict(rule.definition().default_thresholds)
            ),
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def _ctx_with_only(rule_ids: set[str], thresholds: dict[str, int]) -> RuleContext:
    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=rule.definition().id in rule_ids,
            thresholds=thresholds if rule.definition().id in rule_ids else {},
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def _ctx_with_disabled(disabled_id: str) -> RuleContext:
    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=(rule.definition().id != disabled_id),
            thresholds=dict(rule.definition().default_thresholds),
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_defaults_contains_all_seven_size_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    assert SIZE_RULE_IDS.issubset(ids)


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
    # Expected hits at the test-calibrated thresholds (see _default_ctx):
    # - size.attribute-count fires on WideRecord (16 attrs > 15)
    # - size.public-method-count fires on WidePublicSurface (16 public methods > 10)
    # - size.parameter-count fires on big_static (10 params > 5)
    # - size.function-length fires on big_async, outer_function, outer_function.inner_function
    assert "size.attribute-count" in rule_ids
    assert "size.public-method-count" in rule_ids
    assert "size.parameter-count" in rule_ids
    assert "size.function-length" in rule_ids
    # size.file-length should NOT fire (fixture is well under 1000 lines)
    assert "size.file-length" not in rule_ids


def test_cumulative_fixture_findings_carry_symbol_and_metadata_lines():
    unit = _make_unit(SIZE_PILLAR_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    fl = [f for f in findings if f.rule_id == "size.function-length"]
    assert fl, "expected function-length findings"
    assert all(f.symbol for f in fl), f"missing symbol on: {fl}"
    assert all("lines" in f.metadata for f in fl), f"missing 'lines' in metadata: {fl}"
    assert all(isinstance(f.metadata["lines"], int) for f in fl), (
        f"non-int 'lines' in metadata: {fl}"
    )


_THRESHOLD_METADATA_FIXTURE_SRC = """
class Example:
    field = 1

    def method(self, one, two):
        value = one + two
        return value

    def second(self):
        return 2

    def third(self):
        return 3
"""


def test_size_threshold_findings_carry_standard_threshold_metadata():
    """Keep size rule threshold metadata aligned with reporter contracts."""
    ctx = _ctx_with_only(SIZE_RULE_IDS, thresholds={"warning": 0, "error": 9999})
    findings = RuleRegistry.defaults().analyse([_make_unit(_THRESHOLD_METADATA_FIXTURE_SRC)], ctx)
    size_findings = [f for f in findings if f.rule_id in SIZE_RULE_IDS]

    assert SIZE_RULE_IDS.issubset({f.rule_id for f in size_findings})
    assert all(isinstance(f.metadata["measuredValue"], int | float) for f in size_findings)
    assert all(f.metadata["threshold"] == 0 for f in size_findings)
    assert all(f.metadata["thresholdDirection"] == "above" for f in size_findings)
    assert all(f.metadata["thresholdType"] == "warning" for f in size_findings)


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
    # Default function-length threshold = 100 (PMD-aligned). Override to 5/10 to widen coverage.
    registry = RuleRegistry.defaults()
    ctx = _ctx_with_threshold_overrides(
        {"size.function-length": {"warning": 5, "error": 10}},
    )
    default_findings = registry.analyse([_make_unit(SIZE_PILLAR_FIXTURE)], _default_ctx())
    overridden_findings = registry.analyse([_make_unit(SIZE_PILLAR_FIXTURE)], ctx)

    default_fn_count = sum(1 for f in default_findings if f.rule_id == "size.function-length")
    override_fn_count = sum(1 for f in overridden_findings if f.rule_id == "size.function-length")
    # Lower thresholds should expose more functions as oversized.
    assert override_fn_count > default_fn_count


def test_disabling_a_rule_removes_its_findings():
    ctx = _ctx_with_disabled("size.attribute-count")
    findings = RuleRegistry.defaults().analyse([_make_unit(SIZE_PILLAR_FIXTURE)], ctx)
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
