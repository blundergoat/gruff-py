import ast

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.security.unsanitized_markdown_interpolation_rule import (
    UnsanitizedMarkdownInterpolationRule,
)
from gruffpy.source.source_file import SourceFile


def _unit(source: str) -> AnalysisUnit:
    tree = ast.parse(source)
    file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=file, source=source, tree=tree)


def _ctx() -> RuleContext:
    rule = UnsanitizedMarkdownInterpolationRule()
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(enabled=True)}),
    )


def _analyse(source: str):
    return UnsanitizedMarkdownInterpolationRule().analyse(_unit(source), _ctx())


def test_raw_label_and_url_fire_per_slot():
    src = 'def render(title, url):\n    return f"[{title}]({url})"\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"]


def test_call_wrapped_label_fires_only_on_url():
    src = 'def render(title, url):\n    return f"[{clean(title)}]({url})"\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_literal_label_with_raw_url_fires_on_url_slot():
    src = 'def render(url):\n    return f"[docs]({url})"\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_literal_label_with_wrapped_url_is_clean():
    src = 'def render(url):\n    return f"[docs]({quote(url)})"\n'
    assert _analyse(src) == []


def test_fully_literal_link_is_clean():
    src = 'LINK = f"[docs](https://example.test/docs)"\n'
    assert _analyse(src) == []


def test_interpolation_outside_link_shape_is_clean():
    src = 'def render(name):\n    return f"Hello [{name}], welcome"\n'
    assert _analyse(src) == []


def test_attribute_value_in_label_fires():
    src = 'def render(finding):\n    return f"[{finding.path}]({finding.url})"\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"]


def test_format_call_with_raw_slots_fires():
    src = 'def render(title, url):\n    return "[{}]({})".format(title, url)\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"]


def test_format_call_with_keyword_and_call_is_clean_per_slot():
    src = (
        "def render(title, url):\n"
        '    return "[{label}]({url})".format(label=clean(title), url=quote(url))\n'
    )
    assert _analyse(src) == []


def test_format_positional_field_with_attribute_fires_per_slot():
    src = 'def render(item):\n    return "[{0.name}]({0.url})".format(item)\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"]


def test_format_positional_field_with_index_fires_per_slot():
    src = 'def render(item):\n    return "[{0[name]}]({0[url]})".format(item)\n'
    findings = _analyse(src)
    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"]


def test_definition_is_enabled_advisory_medium_security():
    definition = UnsanitizedMarkdownInterpolationRule().definition()
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "medium"
    assert definition.pillar.value == "security"
    assert definition.default_enabled is True
