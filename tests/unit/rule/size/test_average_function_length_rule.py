import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.average_function_length_rule import AverageFunctionLengthRule
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


def _ctx(threshold: int = 30) -> RuleContext:
    """Build a rule context with the average function length rule enabled at an error threshold.

    Args:
        threshold: Value the rule allows before it reports; defaults to 30.

    Returns:
        A context whose config enables only the average function length rule at that threshold.
    """
    rule = AverageFunctionLengthRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_class_with_short_methods_emits_no_finding():
    """Report nothing for a class whose two methods are two lines each."""
    source = "class C:\n    def a(self):\n        return 1\n    def b(self):\n        return 2\n"
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx()) == []


def test_class_with_long_methods_emits_error():
    """Report one error finding, with three methods averaging 9.0 lines, against a threshold of 5."""
    body = "\n".join(["        x = 1"] * 8)
    source = f"class C:\n    def a(self):\n{body}\n    def b(self):\n{body}\n    def c(self):\n{body}\n"
    findings = AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.ERROR
    assert f.metadata["methodCount"] == 3
    assert f.metadata["averageLines"] == 9.0  # each method is 9 lines (def + 8 body)


def test_class_above_error_threshold_emits_error():
    """Report one error finding for three 26-line methods against a threshold of 5."""
    body = "\n".join(["        x = 1"] * 25)
    source = f"class C:\n    def a(self):\n{body}\n    def b(self):\n{body}\n    def c(self):\n{body}\n"
    findings = AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR


def test_class_with_one_long_method_emits_nothing():
    """Report nothing for a class whose only method is 26 lines long against a threshold of 5."""
    body = "\n".join(["        x = 1"] * 25)
    source = f"class C:\n    def a(self):\n{body}\n"
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5)) == []


def test_class_with_no_methods_emits_nothing():
    """Report nothing for a class with attributes but no methods."""
    source = "class C:\n    x = 1\n    y = 2\n"
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5)) == []


def test_nested_class_with_too_few_methods_skipped():
    """Report nothing for a nested class whose only method is long."""
    body = "\n".join(["            x = 1"] * 10)
    source = f"class Outer:\n    class Inner:\n        def m(self):\n{body}\n"
    findings = AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=5))
    assert findings == []


def _documented_method(name: str) -> str:
    """Return source for a method named name with a four-line docstring, twenty comment lines and one return statement.

    Args:
        name: Method name.

    Returns:
        The method source, indented to sit inside a class body.
    """
    doc = '        """Returns a value.\n\n        The single statement below is the whole method.\n        """'
    comments = "\n".join(["        # Explain this step."] * 20)
    return f"    def {name}(self):\n{doc}\n{comments}\n        return 1\n"


def test_documentation_does_not_lengthen_the_average():
    """Report nothing for three documented one-statement methods against a threshold of 2."""
    source = "class C:\n" + _documented_method("a") + _documented_method("b") + _documented_method("c")
    assert AverageFunctionLengthRule().analyse(_make_unit(source), _ctx(threshold=2)) == []
