import ast
from typing import Any

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

_THRESHOLD_RULE_IDS = {
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.nesting-depth",
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
    """Parse source into a Python analysis unit for threshold_contract.py, linking every non-root AST node to its parent.

    Args:
        source: Python source to parse.

    Returns:
        The unit, whose non-root tree nodes carry a parent attribute.
        Attaching links can overwrite parents on shared AST operator and context nodes, including nodes in previously parsed trees.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # Rules use this dynamic AST attribute to recover enclosing symbols.
    return AnalysisUnit(
        file=SourceFile(
            absolute_path="/threshold_contract.py",
            display_path="threshold_contract.py",
            type="python",
        ),
        source=source,
        tree=tree,
    )


def _severity_threshold_for(rule_id: str) -> SeverityThreshold | None:
    """Give a threshold rule an error threshold of 0, so any positive measured value fires.

    Args:
        rule_id: Rule to configure.

    Returns:
        An error threshold of 0 for a rule in the threshold set; None for any other rule.
    """
    # These overrides let the contract tests inspect threshold metadata on findings from the shared fixture.
    if rule_id in _THRESHOLD_RULE_IDS:
        return SeverityThreshold(0, Severity.ERROR)
    return None


def _threshold_ctx() -> RuleContext:
    """Build a rule context that enables only the size and complexity threshold rules, each set to fire above 0.

    Returns:
        The rule context, rooted at /.
    """
    registry = RuleRegistry.defaults()
    rules = {
        rule.definition().id: RuleSettings(
            enabled=rule.definition().id in _THRESHOLD_RULE_IDS,
            severity_threshold=_severity_threshold_for(rule.definition().id),
        )
        for rule in registry.all()
    }
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def _number_is_rendered(value: Any, message: str) -> bool:
    """Check whether a message shows a number as written or rounded to zero, one or two decimal places.

    Args:
        value: Value expected in the message.
        message: Finding message to search.

    Returns:
        True when one of those spellings appears as a substring; False otherwise, including for nonnumeric values.
    """
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
    """Run the enabled threshold rules over the shared source and keep at most one finding per rule.

    Returns:
        The last finding for each reporting threshold rule, keyed by rule ID. Rules that emit no findings have no entry.
    """
    findings = RuleRegistry.defaults().analyse([_unit(_SOURCE)], _threshold_ctx())
    return {finding.rule_id: finding for finding in findings if finding.rule_id in _THRESHOLD_RULE_IDS}


def test_threshold_findings_cover_every_size_and_complexity_rule() -> None:
    """Report a finding for every size and complexity threshold rule from the shared source.

    Returns:
        None. Checks that the shared fixture produces a finding for every configured size and complexity threshold rule.
    """
    findings = _findings_by_rule_id()
    assert findings.keys() >= _THRESHOLD_RULE_IDS


@pytest.mark.parametrize(
    "rule_id",
    sorted(_THRESHOLD_RULE_IDS),
    ids=lambda r: r,
)
def test_size_and_complexity_finding_has_standard_threshold_metadata(rule_id: str) -> None:
    """Give each threshold rule's finding numeric measured and threshold values, an above or below direction and a warning or error type.

    Args:
        rule_id: Size or complexity threshold rule; the cases cover each one.

    Returns:
        None. Checks the two numeric metadata fields and the allowed direction and severity values.
    """
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
    """Find a written or rounded spelling of the measured value and of the threshold in each threshold rule's finding message.

    Args:
        rule_id: Size or complexity threshold rule; the cases cover each one.

    Returns:
        None. Checks that the finding message contains a rendering of both the measured value and the threshold.
    """
    finding = _findings_by_rule_id()[rule_id]
    metadata = finding.metadata
    assert _number_is_rendered(metadata["threshold"], finding.message)
    assert _number_is_rendered(metadata["measuredValue"], finding.message)
