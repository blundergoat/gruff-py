import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.size.parameter_count_rule import ParameterCountRule
from gruffpy.source.source_file import SourceFile


def _make_unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]  # AST parent links
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx(threshold: int = 5) -> RuleContext:
    rule = ParameterCountRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_function_within_threshold_emits_no_finding():
    source = "def f(a, b, c):\n    return a\n"
    assert ParameterCountRule().analyse(_make_unit(source), _ctx()) == []


def test_function_above_threshold_emits_error():
    source = "def f(a, b, c, d, e, ff):\n    return a\n"
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.ERROR
    assert f.metadata["parameters"] == 6


def test_function_above_error_emits_error():
    source = "def f(a, b, c, d, e, ff, g, h, i):\n    return a\n"
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["parameters"] == 9


def test_method_excludes_self():
    # 5 visible params + self -> 5, no finding
    source = "class C:\n    def m(self, a, b, c, d, e):\n        return a\n"
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert findings == []


def test_classmethod_excludes_cls():
    source = "class C:\n    @classmethod\n    def m(cls, a, b, c, d, e):\n        return a\n"
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert findings == []


def test_module_level_function_does_not_exclude_first_arg():
    # 5 module-level params -> at threshold (not above) -> no finding
    source = "def f(self, a, b, c, d):\n    return a\n"
    # 'self' is just a name when not inside a class - counts as a parameter
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert findings == []


def test_varargs_and_kwargs_each_count_as_one():
    source = "def f(a, b, c, *args, **kwargs):\n    return a\n"
    # 3 + 1 (*args) + 1 (**kwargs) = 5 -> at threshold, no finding
    assert ParameterCountRule().analyse(_make_unit(source), _ctx()) == []

    source2 = "def f(a, b, c, d, *args, **kwargs):\n    return a\n"
    # 4 + 1 + 1 = 6 -> warning
    findings = ParameterCountRule().analyse(_make_unit(source2), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameters"] == 6


def test_kwonly_args_count():
    source = "def f(a, b, *, c, d, e, ff):\n    return a\n"
    # 2 positional + 4 kwonly = 6 -> warning
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameters"] == 6


def test_positional_only_args_count():
    source = "def f(a, b, c, /, d, e, ff):\n    return a\n"
    # 3 posonly + 3 = 6 -> warning
    findings = ParameterCountRule().analyse(_make_unit(source), _ctx())
    assert len(findings) == 1
    assert findings[0].metadata["parameters"] == 6
