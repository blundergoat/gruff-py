import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.class_length_rule import ClassLengthRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    """Parse source, link every non-root AST node to its parent and wrap it as an analysis unit for ``x.py``.

    Args:
        source: Python source to parse.

    Returns:
        A unit for ``x.py`` whose AST nodes carry parent links.
    """
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 300) -> RuleContext:
    """Build a rule context with the class length rule enabled at an error threshold.

    Args:
        threshold: Value the rule allows before it reports; defaults to 300.

    Returns:
        A context whose config enables only the class length rule at that threshold.
    """
    rule = ClassLengthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_short_class_emits_no_finding():
    """Report nothing for a two-line class against a threshold of 5."""
    source = "class C:\n    x = 1\n"
    assert ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=5)) == []


def test_long_class_emits_error():
    """Report one error finding on ``C``, measuring 11 lines, for ten assignments against a threshold of 5."""
    body = "\n".join(["    x = 1"] * 10)
    source = f"class C:\n{body}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.ERROR
    assert f.symbol == "C"
    assert f.metadata["lines"] == 11


def test_long_class_emits_error_above_error_threshold():
    """Report one error finding for thirty assignments against a threshold of 5."""
    body = "\n".join(["    x = 1"] * 30)
    source = f"class C:\n{body}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR


def test_nested_class_emits_qualified_symbol():
    """Report both ``Outer`` and ``Outer.Inner`` when a nested class is long."""
    inner = "\n".join(["        x = 1"] * 10)
    source = f"class Outer:\n    class Inner:\n{inner}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    symbols = {f.symbol for f in findings}
    assert "Outer" in symbols
    assert "Outer.Inner" in symbols


def test_decorator_lines_are_free_in_class_length():
    """Measure a decorated class with five body lines at 6 lines while the finding starts at line 1."""
    body = "\n".join(["    x = 1"] * 5)
    source = f"@dataclass\nclass C:\n{body}\n"
    findings = ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    f = findings[0]
    # class line + 5 body lines = 6; the decorator is free
    assert f.metadata["lines"] == 6
    assert f.line == 1


def test_documented_class_is_measured_by_its_code_lines():
    """Report a documented class with six code lines at a threshold of 5 but not at 6."""
    docstring = '    """Holds five values.\n\n    Each attribute below is code.\n    """'
    comments = "\n".join(["    # Explain the next value."] * 10)
    body = "\n".join(["    x = 1"] * 5)
    source = f"class C:\n{docstring}\n{comments}\n{body}\n"
    assert ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=6)) == []
    assert len(ClassLengthRule().analyse(_make_unit(source), _ctx(threshold=5))) == 1
