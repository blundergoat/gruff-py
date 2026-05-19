import ast
import math

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.complexity.maintainability_index_rule import (
    MaintainabilityIndexRule,
    maintainability_index_for,
)
from gruffpy.rule.context import RuleContext
from gruffpy.source.source_file import SourceFile


def _first_fn(source: str) -> ast.FunctionDef:
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            return node
    raise AssertionError("no function found")


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(warning: int = 80, error: int = 70) -> RuleContext:
    rule = MaintainabilityIndexRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                thresholds={"warning": warning, "error": error},
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def _branched_body(branch_count: int, with_elif: bool = False) -> str:
    """Return a function body that contains ``branch_count`` if/else branches."""
    lines: list[str] = []
    for i in range(branch_count):
        lines.append(f"    if a{i} > b{i}:")
        lines.append(f"        x = a{i} + b{i}")
        if with_elif:
            lines.append(f"        x = a{i} + b{i} * c{i} - d{i}")
            lines.append(f"    elif a{i} < b{i}:")
            lines.append(f"        x = a{i} - b{i} / c{i} + d{i}")
        else:
            lines.append("    else:")
            lines.append(f"        x = a{i} - b{i}")
    return "def f():\n" + "\n".join(lines) + "\n    return x\n"


def test_trivial_function_has_max_mi():
    # Simple short function: low HV, CC=1, low LOC -> MI close to 100 (clamped).
    src = "def f(x):\n    return x + 1\n"
    mi = maintainability_index_for(_first_fn(src))
    assert mi == 100.0  # clamped at upper bound


_MI_CLAMP_MAX = 100.0


def test_mi_formula_matches_canonical_values():
    """Trace a known case to verify the formula.

    For `f(x): return x + 1`:
    - HV = 4.7548..., ln(HV) ~= 1.559
    - CC = 1
    - LOC = 2 (def line + return line, raw span)
    - MI = 171 - 5.2*1.559 - 0.23*1 - 16.2*ln(2)
         = 171 - 8.107 - 0.23 - 16.2*0.693
         = 171 - 8.107 - 0.23 - 11.226
         = 151.4  -> clamped to 100
    """
    src = "def f(x):\n    return x + 1\n"
    raw = 171 - 5.2 * math.log(4.7548875) - 0.23 * 1 - 16.2 * math.log(2)
    assert raw > _MI_CLAMP_MAX  # would clamp
    assert maintainability_index_for(_first_fn(src)) == _MI_CLAMP_MAX


def test_complex_function_lowers_mi():
    # Bigger function should have lower (worse) MI.
    src = _branched_body(40)
    mi = maintainability_index_for(_first_fn(src))
    assert mi < 80.0  # below default warning


def test_warning_finding_emitted_for_low_mi():
    # Use 40-branch fixture so MI is guaranteed below default warning=80.
    src = _branched_body(40)
    findings = MaintainabilityIndexRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.pillar == Pillar.MAINTAINABILITY  # separate pillar
    assert "maintainabilityIndex" in finding.metadata
    assert finding.severity in (Severity.WARNING, Severity.ERROR)


def test_error_finding_emitted_for_very_low_mi():
    # Aggressively low MI: many branches and operators.
    src = _branched_body(80, with_elif=True)
    findings = MaintainabilityIndexRule().analyse(_make_unit(src), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR


def test_lower_threshold_means_worse_mi_is_threshold():
    # Threshold semantics: lower MI = worse.
    src = "def f(x):\n    return x + 1\n"  # MI = 100 (clamped)
    # warning threshold = 100 -> 100 is NOT below 100, no finding
    findings = MaintainabilityIndexRule().analyse(_make_unit(src), _ctx(warning=100, error=80))
    assert findings == []
    # warning threshold = 110 -> 100 is below 110, finding emitted
    findings2 = MaintainabilityIndexRule().analyse(_make_unit(src), _ctx(warning=110, error=80))
    assert len(findings2) == 1


def test_definition_uses_default_thresholds():
    d = MaintainabilityIndexRule().definition()
    assert d.id == "complexity.maintainability-index"
    assert d.pillar == Pillar.MAINTAINABILITY  # NOT complexity!
    assert d.default_thresholds == {"warning": 80, "error": 70}
