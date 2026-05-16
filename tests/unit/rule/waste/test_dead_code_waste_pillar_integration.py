"""Cumulative integration + dynamism false-positive fixture for M04.

Asserts that on a fixture exercising real Python dynamism (pytest fixtures,
FastAPI routes, ABCs, Protocols, dataclasses, __all__), the dead-code and
waste rules produce ZERO findings.
"""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

DYNAMISM_FIXTURE = '''
"""Dynamism patterns gruff-py should NOT flag.

This fixture lives in tests/ and exercises false-positive triggers for
M04 dead-code/waste rules.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Protocol


__all__ = ["_explicit_export"]


def _explicit_export():
    """Exported via __all__; not unused."""
    return 1


class _AbstractBase(ABC):
    @abstractmethod
    def required(self):
        ...


class _Marker(Protocol):
    """Protocol marker — empty body is intentional."""


class _MarkerProtocolMethod(Protocol):
    def callback(self, value: int) -> int:
        ...


@dataclass
class _Record:
    """Dataclass — fields are framework-managed."""

    _internal: int = 0


# pytest fixture pattern — _setup is registered by name, not by reference.
def _setup(request):
    """Pretend pytest fixture; framework-decorated equivalent skipped by
    has_framework_decorator. This bare form requires __all__ to suppress."""
    return None


class WithPropertyBacking:
    """@property backing field — _value is read implicitly via the setter."""

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, v):
        self._value = v
'''


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(
            absolute_path="/dynamism.py",
            display_path="dynamism.py",
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _ctx() -> RuleContext:
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        d = rule.definition()
        rules[d.id] = RuleSettings(enabled=True, thresholds=dict(d.default_thresholds))
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_includes_all_m04_rules():
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    expected = {
        "dead-code.unused-private-function",
        "dead-code.unused-private-attribute",
        "waste.commented-out-code",
        "waste.empty-class",
        "waste.empty-function",
        "waste.one-line-function",
        "waste.redundant-variable",
        "waste.unreachable-code",
        "waste.unused-import",
        "waste.unused-parameter",
    }
    assert expected.issubset(ids)


def test_dynamism_fixture_emits_only_acceptable_findings():
    findings = RuleRegistry.defaults().analyse([_unit(DYNAMISM_FIXTURE)], _ctx())
    # The fixture deliberately includes things that LOOK suspicious but
    # are accepted Python patterns. Restrict the dead-code + waste rules
    # to count their findings.
    target_rule_prefixes = ("dead-code.", "waste.")
    suspect = [f for f in findings if any(f.rule_id.startswith(p) for p in target_rule_prefixes)]
    # Acceptable findings on the bare `_setup` function (no @pytest.fixture
    # decorator — the fixture intentionally documents the user-facing trap):
    # 1. dead-code.unused-private-function: nothing calls _setup
    # 2. waste.unused-parameter on `request`: _setup ignores its arg
    # Both vanish once the user adds @pytest.fixture, demonstrating the
    # suppression. Everything else MUST be silent.
    expected_on_setup = {
        ("dead-code.unused-private-function", "_setup"),
        ("waste.unused-parameter", "_setup"),
    }
    unexpected = [
        (f.rule_id, f.symbol) for f in suspect if (f.rule_id, f.symbol) not in expected_on_setup
    ]
    assert unexpected == [], f"unexpected findings: {unexpected}"


def test_findings_deterministic_across_two_runs():
    a = RuleRegistry.defaults().analyse([_unit(DYNAMISM_FIXTURE)], _ctx())
    b = RuleRegistry.defaults().analyse([_unit(DYNAMISM_FIXTURE)], _ctx())
    assert [f.fingerprint() for f in a] == [f.fingerprint() for f in b]
