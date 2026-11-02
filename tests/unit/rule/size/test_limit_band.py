"""The two bands every size and complexity finding reports in, and the measures M14 changed.

FAMILY-CONTRACT.md section 12, "Size and complexity findings in two bands": just over its limit a unit gets an advisory
notice not to grow; at one and a half times its limit or more it keeps its severity and the advice to split or simplify.
"""

import ast
import re
from collections.abc import Callable

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity.cognitive_complexity_rule import CognitiveComplexityRule
from gruffpy.rule.complexity.cyclomatic_complexity_rule import CyclomaticComplexityRule
from gruffpy.rule.complexity.nesting_depth_rule import NestingDepthRule
from gruffpy.rule.context import RuleContext
from gruffpy.rule.rule import Rule
from gruffpy.rule.size import _band
from gruffpy.rule.size.attribute_count_rule import AttributeCountRule
from gruffpy.rule.size.class_length_rule import ClassLengthRule
from gruffpy.rule.size.file_length_rule import FileLengthRule
from gruffpy.rule.size.function_length_rule import FunctionLengthRule
from gruffpy.rule.size.parameter_count_rule import ParameterCountRule
from gruffpy.rule.size.public_method_count_rule import PublicMethodCountRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``band.py``.

    Args:
        source: Python source to parse.

    Returns:
        A unit for ``band.py`` whose AST nodes carry parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links, as the parser attaches them
    return AnalysisUnit(file=SourceFile(absolute_path="/band.py", display_path="band.py", type="python"), source=source, tree=tree)


def _ctx(rule: Rule, settings: RuleSettings) -> RuleContext:
    """Build a rule context whose config holds settings for rule alone.

    Args:
        rule: Rule whose id keys the settings.
        settings: Settings applied to that rule.

    Returns:
        A context whose config enables only that rule with those settings.
    """
    return RuleContext(project_root="/", config=AnalysisConfig(rules={rule.definition().id: settings}))


def _only(rule: Rule, source: str, settings: RuleSettings) -> Finding:
    """Run rule over source with settings and return its single finding.

    Args:
        rule: Rule to run.
        source: Python source to analyse.
        settings: Settings for the rule.

    Returns:
        The one finding the rule reports.

    Raises:
        AssertionError: The rule reports no finding or more than one.
    """
    findings = rule.analyse(_make_unit(source), _ctx(rule, settings))
    assert len(findings) == 1, findings
    return findings[0]


def _assignments(count: int) -> str:
    """Return module source with count numbered assignments, one per line.

    Args:
        count: Number of items to generate.

    Returns:
        Source holding one assignment per line.
    """
    return "".join(f"v{i} = {i}\n" for i in range(count))


def _class_of_lines(count: int) -> str:
    """Return source for a class ``C`` spanning count lines: the class line plus count minus one attributes.

    Args:
        count: Lines the class should span.

    Returns:
        Source for ``C`` with count minus one attribute assignments.
    """
    return "class C:\n" + "".join(f"    a{i} = {i}\n" for i in range(count - 1))


def _function_of_statements(count: int) -> str:
    """Return source for a function ``f`` of count lines: the ``def``, count minus two increments and a return.

    Args:
        count: Lines the function should span.

    Returns:
        Source for ``f`` spanning count lines.
    """
    return "def f(x):\n" + "".join("    x += 1\n" for _ in range(count - 2)) + "    return x\n"


def _function_with_parameters(count: int) -> str:
    """Return source for a function ``f`` with count numbered parameters that returns the first.

    Args:
        count: Number of items to generate.

    Returns:
        Source for ``f`` taking count parameters.
    """
    return "def f(" + ", ".join(f"p{i}" for i in range(count)) + "):\n    return p0\n"


def _class_with_attributes(count: int) -> str:
    """Return source for a class ``C`` with count annotated attributes.

    Args:
        count: Number of items to generate.

    Returns:
        Source for ``C`` with count annotated attribute lines.
    """
    return "class C:\n" + "".join(f"    a{i}: int = {i}\n" for i in range(count))


def _class_with_public_methods(count: int) -> str:
    """Return source for a class ``C`` with count public methods, each returning its index.

    Args:
        count: Number of items to generate.

    Returns:
        Source for ``C`` with count two-line methods.
    """
    return "class C:\n" + "".join(f"    def m{i}(self):\n        return {i}\n" for i in range(count))


def _function_with_branches(count: int) -> str:
    """Return source for a function ``f`` with count sequential ``if`` branches on ``x``.

    Args:
        count: Number of items to generate.

    Returns:
        Source for ``f`` with count branches before its return.
    """
    return "def f(x):\n    y = 0\n" + "".join(f"    if x == {i}:\n        y += {i}\n" for i in range(count)) + "    return y\n"


def _function_nested_to(depth: int) -> str:
    """Return source for a function ``f`` whose ``if`` statements nest depth levels deep before the return.

    Args:
        depth: Nesting depth of the innermost statement.

    Returns:
        Source for ``f`` with depth nested ``if`` statements.
    """
    return "def f(x):\n" + "".join("    " * (level + 1) + f"if x > {level}:\n" for level in range(depth)) + "    " * (depth + 1) + "return x\n"


# rule, limit, builder argument for a lower-band unit, builder argument for an upper-band unit, source builder, lower advice,
# upper advice. Cyclomatic complexity is one more than its branch count, so its arguments sit one below the measured value.
BAND_FIELDS = ("rule", "limit", "lower", "upper", "build", "lower_advice", "upper_advice")


def _case_id(case: object) -> str | None:
    """Return a case value's ``ID`` attribute as its parametrize id, or None when it has none.

    Args:
        case: One parametrize argument value; a rule instance carries ``ID``.

    Returns:
        The ``ID`` string, or None for a value without one.
    """
    return getattr(case, "ID", None)


BAND_CASES: list[tuple[Rule, int, int, int, Callable[[int], str], str, str]] = [
    (FileLengthRule(), 1000, 1100, 2000, _assignments, _band.LOWER_FILE, _band.SPLIT_FILE),
    (ClassLengthRule(), 1000, 1100, 2000, _class_of_lines, _band.LOWER_CLASS, _band.SPLIT_CLASS),
    (FunctionLengthRule(), 100, 110, 200, _function_of_statements, _band.LOWER_FUNCTION, _band.SPLIT_FUNCTION),
    (ParameterCountRule(), 10, 11, 20, _function_with_parameters, _band.LOWER_PARAMETER, _band.GROUP_PARAMETERS),
    (AttributeCountRule(), 15, 16, 30, _class_with_attributes, _band.LOWER_ATTRIBUTE, _band.SPLIT_CLASS),
    (PublicMethodCountRule(), 10, 11, 20, _class_with_public_methods, _band.LOWER_PUBLIC_METHOD, _band.SPLIT_CLASS),
    (CognitiveComplexityRule(), 30, 31, 60, _function_with_branches, _band.LOWER_FUNCTION, _band.SIMPLIFY_PATH),
    (CyclomaticComplexityRule(), 20, 20, 39, _function_with_branches, _band.LOWER_FUNCTION, _band.SIMPLIFY_PATH),
    (NestingDepthRule(), 6, 7, 12, _function_nested_to, _band.LOWER_FUNCTION, _band.SIMPLIFY_PATH),
]


@pytest.mark.parametrize(BAND_FIELDS, BAND_CASES, ids=_case_id)
def test_each_rule_just_over_its_limit_reports_the_lower_band_notice(
    rule: Rule, limit: int, lower: int, upper: int, build: Callable[[int], str], lower_advice: str, upper_advice: str
) -> None:
    """Report a unit just over each rule's limit as one advisory lower-band finding carrying that rule's lower advice.

    Args:
        rule: Size or complexity rule under test.
        limit: Error threshold the context sets for it.
        lower: Builder argument for a unit measuring under one and a half times the limit.
        upper: Builder argument for a unit measuring at least one and a half times the limit.
        build: Function that turns a count into source.
        lower_advice: Remediation expected in the lower band.
        upper_advice: Remediation expected in the upper band.
    """
    near = _only(rule, build(lower), RuleSettings(enabled=True, severity_threshold=SeverityThreshold(limit, Severity.ERROR)))

    assert near.metadata["measuredValue"] < 1.5 * limit
    assert (near.metadata[_band.LIMIT_BAND_KEY], near.severity, near.remediation) == (_band.LOWER, Severity.ADVISORY, lower_advice)


@pytest.mark.parametrize(BAND_FIELDS, BAND_CASES, ids=_case_id)
def test_each_rule_at_twice_its_limit_keeps_its_severity_and_says_split_or_simplify(
    rule: Rule, limit: int, lower: int, upper: int, build: Callable[[int], str], lower_advice: str, upper_advice: str
) -> None:
    """Report a unit at one and a half times each rule's limit or more as one error upper-band finding carrying the upper advice.

    Neither advice text mentions raising a threshold, ignoring, excluding or extracting.

    Args:
        rule: Size or complexity rule under test.
        limit: Error threshold the context sets for it.
        lower: Builder argument for a unit measuring under one and a half times the limit.
        upper: Builder argument for a unit measuring at least one and a half times the limit.
        build: Function that turns a count into source.
        lower_advice: Remediation expected in the lower band.
        upper_advice: Remediation expected in the upper band.
    """
    far = _only(rule, build(upper), RuleSettings(enabled=True, severity_threshold=SeverityThreshold(limit, Severity.ERROR)))

    assert far.metadata["measuredValue"] >= 1.5 * limit
    assert (far.metadata[_band.LIMIT_BAND_KEY], far.severity, far.remediation) == (_band.UPPER, Severity.ERROR, upper_advice)
    assert not re.search(r"raise|threshold|ignore|exclude|extract", f"{lower_advice} {upper_advice}", re.IGNORECASE)


@pytest.mark.parametrize(("lines", "band", "severity"), [(110, _band.LOWER, Severity.ADVISORY), (160, _band.UPPER, Severity.WARNING)])
def test_a_configured_severity_applies_only_in_the_upper_band(lines: int, band: str, severity: Severity) -> None:
    """Report a 110-line function as advisory and a 160-line one with the configured warning, each message naming the threshold of 100.

    Args:
        lines: Statement count the function builder receives.
        band: Expected limit band.
        severity: Expected severity: advisory in the lower band, the configured warning in the upper.
    """
    settings = RuleSettings(enabled=True, severity_threshold=SeverityThreshold(100, Severity.WARNING))
    finding = _only(FunctionLengthRule(), _function_of_statements(lines), settings)

    assert (finding.metadata[_band.LIMIT_BAND_KEY], finding.severity) == (band, severity)
    # The message names the threshold the value crossed, in both bands.
    assert "above the warning threshold of 100" in finding.message


def test_function_length_counts_a_multi_line_literal_and_call_once() -> None:
    """Count a 130-line dict literal and a 130-line call as one line each, measuring the function at 12 lines."""
    literal = "".join(f"        'key{i}': {i},\n" for i in range(130))
    arguments = "".join(f"        option{i}={i},\n" for i in range(130))
    statements = "".join("    x += 1\n" for _ in range(8))
    source = f"def f(x):\n    table = {{\n{literal}    }}\n    configure(\n{arguments}    )\n{statements}    return table\n"
    settings = RuleSettings(enabled=True, severity_threshold=SeverityThreshold(5, Severity.ERROR))

    finding = _only(FunctionLengthRule(), source, settings)

    # The def line, the literal, the call, eight statements and the return: twelve logical lines.
    assert finding.metadata["lines"] == 12


def test_function_length_still_reports_101_distinct_statements() -> None:
    """Measure a 102-line function of distinct statements at 102 lines against a threshold of 100."""
    settings = RuleSettings(enabled=True, severity_threshold=SeverityThreshold(100, Severity.ERROR))
    finding = _only(FunctionLengthRule(), _function_of_statements(102), settings)

    assert finding.metadata["lines"] == 102


def test_public_method_count_counts_each_name_once() -> None:
    """Count six property pairs and one overloaded method as 7 public names, not fifteen definitions."""
    properties = "".join(
        f"    @property\n    def p{i}(self):\n        return {i}\n    @p{i}.setter\n    def p{i}(self, value):\n        pass\n" for i in range(6)
    )
    overloads = (
        "    @overload\n    def fetch(self, key: int) -> int: ...\n"
        "    @overload\n    def fetch(self, key: str) -> str: ...\n"
        "    def fetch(self, key):\n        return key\n"
    )
    source = f"from typing import overload\n\nclass Settings:\n{properties}{overloads}"
    settings = RuleSettings(enabled=True, severity_threshold=SeverityThreshold(6, Severity.ERROR))

    finding = _only(PublicMethodCountRule(), source, settings)

    # Six properties and one overloaded method are seven public names, not fifteen definitions.
    assert finding.metadata["publicMethods"] == 7
