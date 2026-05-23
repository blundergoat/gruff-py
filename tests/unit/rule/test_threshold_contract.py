import ast
from typing import Any

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

_THRESHOLD_RULE_IDS = {
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.halstead-volume",
    "complexity.maintainability-index",
    "complexity.nesting-depth",
    "complexity.npath",
    "size.attribute-count",
    "size.average-function-length",
    "size.class-length",
    "size.file-length",
    "size.function-length",
    "size.parameter-count",
    "size.public-method-count",
}

_SOURCE = """
class Example:
    field = 1

    def one(self, alpha, beta):
        if alpha:
            return beta + 1
        return alpha + beta

    def two(self):
        return 2

    def three(self):
        return 3


def sample(value, other):
    if value and other:
        if value > other:
            return value * other
    return value + other
"""


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    return AnalysisUnit(
        file=SourceFile(
            absolute_path="/threshold_contract.py",
            display_path="threshold_contract.py",
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _thresholds_for(rule_id: str) -> dict[str, int]:
    if rule_id == "complexity.maintainability-index":
        return {"warning": 101, "error": 0}
    if rule_id in _THRESHOLD_RULE_IDS:
        return {"warning": 0, "error": 9999}
    return {}


def _threshold_ctx() -> RuleContext:
    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=rule.definition().id in _THRESHOLD_RULE_IDS,
            thresholds=_thresholds_for(rule.definition().id),
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def _number_is_rendered(value: Any, message: str) -> bool:
    if not isinstance(value, (int, float)):
        return False
    candidates = {
        str(value),
        f"{value:.0f}",
        f"{value:.1f}",
        f"{value:.2f}",
    }
    return any(candidate in message for candidate in candidates)


def _findings_by_rule_id() -> dict[str, Finding]:
    findings = RuleRegistry.defaults().analyse([_unit(_SOURCE)], _threshold_ctx())
    return {
        finding.rule_id: finding for finding in findings if finding.rule_id in _THRESHOLD_RULE_IDS
    }


def test_threshold_findings_cover_every_size_and_complexity_rule() -> None:
    findings = _findings_by_rule_id()
    assert findings.keys() >= _THRESHOLD_RULE_IDS


@pytest.mark.parametrize(
    "rule_id",
    sorted(_THRESHOLD_RULE_IDS),
    ids=lambda r: r,
)
def test_size_and_complexity_finding_has_standard_threshold_metadata(rule_id: str) -> None:
    metadata = _findings_by_rule_id()[rule_id].metadata
    assert isinstance(metadata["measuredValue"], int | float)
    assert isinstance(metadata["threshold"], int | float)
    assert metadata["thresholdDirection"] in {"above", "below"}
    assert metadata["thresholdType"] in {"warning", "error"}


@pytest.mark.parametrize(
    "rule_id",
    sorted(_THRESHOLD_RULE_IDS),
    ids=lambda r: r,
)
def test_size_and_complexity_finding_message_mentions_measured_and_threshold(
    rule_id: str,
) -> None:
    finding = _findings_by_rule_id()[rule_id]
    metadata = finding.metadata
    assert _number_is_rendered(metadata["threshold"], finding.message)
    assert _number_is_rendered(metadata["measuredValue"], finding.message)
