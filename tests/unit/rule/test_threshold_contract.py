import ast
from typing import Any

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


def test_size_and_complexity_threshold_findings_share_standard_metadata_contract() -> None:
    findings = RuleRegistry.defaults().analyse([_unit(_SOURCE)], _threshold_ctx())
    by_rule = {
        finding.rule_id: finding for finding in findings if finding.rule_id in _THRESHOLD_RULE_IDS
    }

    assert by_rule.keys() >= _THRESHOLD_RULE_IDS
    for finding in by_rule.values():
        _assert_standard_threshold_metadata(finding)
        _assert_message_mentions_measured_value_and_threshold(finding)


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    return AnalysisUnit(
        file=SourceFile(
            absolute_path="/threshold_contract.py",
            display_path="threshold_contract.py",
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _threshold_ctx() -> RuleContext:
    registry = RuleRegistry.defaults()
    rules: dict[str, RuleSettings] = {}
    for rule in registry.all():
        definition = rule.definition()
        if definition.id == "complexity.maintainability-index":
            thresholds = {"warning": 101, "error": 0}
        elif definition.id in _THRESHOLD_RULE_IDS:
            thresholds = {"warning": 0, "error": 9999}
        else:
            thresholds = {}
        rules[definition.id] = RuleSettings(
            enabled=definition.id in _THRESHOLD_RULE_IDS,
            thresholds=thresholds,
        )
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def _assert_standard_threshold_metadata(finding: Finding) -> None:
    metadata = finding.metadata
    assert isinstance(metadata["measuredValue"], int | float)
    assert isinstance(metadata["threshold"], int | float)
    assert metadata["thresholdDirection"] in {"above", "below"}
    assert metadata["thresholdType"] in {"warning", "error"}


def _assert_message_mentions_measured_value_and_threshold(finding: Finding) -> None:
    metadata = finding.metadata
    assert _number_is_rendered(metadata["threshold"], finding.message)
    assert _number_is_rendered(metadata["measuredValue"], finding.message)


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
