"""Cumulative integration tests covering complexity-pillar registry and metadata behavior."""

import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.source.source_file import SourceFile

COMPLEXITY_RULE_IDS = {
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.nesting-depth",
}

COMPLEXITY_FIXTURE = '''
"""Fixture exercising every complexity rule."""


def shallow(x):
    return x + 1


def too_complex(a, b, c, d, e, f):
    if a and b:
        if c or d:
            if e:
                if f:
                    if a > b:
                        if c < d:
                            if e == f:
                                if a + b > c:
                                    if d + e > f:
                                        return 1
    return 0


def too_long():
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
    x = 31
    x = 32
    return x


def god_method(a, b, c, d, e, f, g, h):
    """Long + parameter-heavy + complex - overlapping size and complexity findings on one symbol."""
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if a > b:
                                        if b > c:
                                            return 1
    if a + b + c + d > 0:
        for i in range(10):
            for j in range(10):
                if i > j:
                    for k in range(10):
                        if k > 0:
                            print(i, j, k)
    return 0
'''


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``integration.py``.

    Args:
        source: Python source to parse.

    Returns:
        The analysis unit.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/integration.py", display_path="integration.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _default_ctx() -> RuleContext:
    """Build a rule context from the registry defaults with five size and complexity thresholds lowered for the fixture.

    Returns:
        The rule context.
    """
    # Single-threshold defaults are too generous for the compact fixture.
    # Override the size + complexity rubrics low enough that the fixture's
    # complex functions fire overlapping size + complexity findings, but high
    # enough that ``shallow`` stays clean.
    overrides = {
        "size.function-length": 15,
        "size.parameter-count": 5,
        "complexity.cyclomatic": 5,
        "complexity.cognitive": 5,
        "complexity.nesting-depth": 2,
    }
    return _ctx_with_threshold_overrides(overrides)


def _ctx_with_threshold_overrides(overrides: dict[str, int]) -> RuleContext:
    """Build a rule context from the registry defaults, enabling each named rule at its override error threshold.

    Each overridden rule keeps its default options.

    Args:
        overrides: Error threshold to set for each rule id.

    Returns:
        The rule context.
    """
    config = AnalysisConfig.from_registry(RuleRegistry.defaults())
    for rule_id, threshold in overrides.items():
        config = config.with_rule_settings(
            rule_id,
            RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
                options=config.rules[rule_id].options,
            ),
        )
    return RuleContext(project_root="/", config=config)


def _ctx_for_complexity_metadata() -> RuleContext:
    """Build a rule context that enables only the three complexity rules, each at an error threshold of 0.

    Every other default rule is disabled.

    Returns:
        The rule context.
    """
    registry = RuleRegistry.defaults()
    rules = {}
    for rule in registry.all():
        rule_id = rule.definition().id
        if rule_id in COMPLEXITY_RULE_IDS:
            threshold = 0
            rules[rule_id] = RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            )
        else:
            rules[rule_id] = RuleSettings(enabled=False)
    return RuleContext(project_root="/", config=AnalysisConfig(rules=rules))


def test_registry_defaults_includes_all_complexity_rules():
    """Register the cognitive, cyclomatic and nesting-depth rules in the default registry."""
    registry = RuleRegistry.defaults()
    ids = {rule.definition().id for rule in registry.all()}
    assert COMPLEXITY_RULE_IDS.issubset(ids)


def test_complexity_rules_emit_findings_on_fixture():
    """Report at least one cyclomatic, cognitive and nesting-depth finding on the fixture under lowered thresholds."""
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    rule_ids = {f.rule_id for f in findings}
    # too_complex should fire at minimum cyclomatic, cognitive, and
    # nesting-depth.
    assert "complexity.cyclomatic" in rule_ids
    assert "complexity.cognitive" in rule_ids
    assert "complexity.nesting-depth" in rule_ids


_METADATA_FIXTURE_SRC = """
def sample(a, b):
    if a + 1 > b - 1:
        if a and b:
            return a * b
    return a + b
"""


def _complexity_findings_with_metadata_ctx() -> list:
    """Analyse the two-branch metadata fixture with only the complexity rules enabled at threshold 0.

    Returns:
        The complexity rules' findings.
    """
    findings = RuleRegistry.defaults().analyse([_make_unit(_METADATA_FIXTURE_SRC)], _ctx_for_complexity_metadata())
    return [f for f in findings if f.rule_id in COMPLEXITY_RULE_IDS]


def test_complexity_metadata_covers_all_complexity_rules():
    """Report a finding from each of the three complexity rules on the metadata fixture."""
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert COMPLEXITY_RULE_IDS.issubset({f.rule_id for f in complexity_findings})


def test_complexity_findings_carry_numeric_measured_value():
    """Give every complexity finding a numeric ``measuredValue``."""
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert all(isinstance(f.metadata["measuredValue"], int | float) for f in complexity_findings)


def test_complexity_findings_carry_error_threshold_type():
    """Mark every complexity finding's threshold type as ``error``."""
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert all(f.metadata["thresholdType"] == "error" for f in complexity_findings)


def test_above_threshold_complexity_findings_carry_above_direction():
    """Record a threshold of 0 and the direction ``above`` on every complexity finding."""
    complexity_findings = _complexity_findings_with_metadata_ctx()
    assert all(f.metadata["threshold"] == 0 for f in complexity_findings)
    assert all(f.metadata["thresholdDirection"] == "above" for f in complexity_findings)


_COMPLEXITY_RULES_FOR_SHALLOW = (
    "complexity.cognitive",
    "complexity.cyclomatic",
    "complexity.nesting-depth",
)


def test_shallow_function_no_complexity_findings():
    """Report no complexity finding on ``shallow`` under the lowered fixture thresholds."""
    unit = _make_unit(COMPLEXITY_FIXTURE)
    findings = RuleRegistry.defaults().analyse([unit], _default_ctx())
    shallow_complexity_findings = [f for f in findings if f.symbol == "shallow" and f.rule_id in _COMPLEXITY_RULES_FOR_SHALLOW]
    assert shallow_complexity_findings == []
