from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.rule.context import RuleContext
from gruffpy.rule.docs.dataclass_attributes_rule import DataclassAttributesRule
from tests.unit.rule.docs._helpers import default_ctx, make_unit


def test_public_dataclass_without_attribute_docs_emits():
    """Report an undocumented three-field public dataclass once, listing every field as missing."""
    src = """\
from dataclasses import dataclass

@dataclass(frozen=True)
class AnalysisReport:
    tool_version: str
    findings: tuple[str, ...]
    exit_code: int
"""

    findings = DataclassAttributesRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].symbol == "AnalysisReport"
    assert findings[0].metadata["fieldCount"] == 3
    assert findings[0].metadata["missingFields"] == ["tool_version", "findings", "exit_code"]


def test_attributes_section_is_accepted():
    """Report nothing when an ``Attributes`` section documents every field."""
    src = '''\
from dataclasses import dataclass

@dataclass(frozen=True)
class AnalysisReport:
    """Immutable payload shared by reporters.

    Attributes:
        tool_version: Version that produced the report.
        findings: Stable finding list.
        exit_code: Process exit code.
    """

    tool_version: str
    findings: tuple[str, ...]
    exit_code: int
'''

    assert DataclassAttributesRule().analyse(make_unit(src), default_ctx()) == []


def test_bullet_field_list_is_accepted_by_default():
    """Report nothing when a bullet list documents every field under the default options."""
    src = '''\
from dataclasses import dataclass

@dataclass
class Payload:
    """Transport payload.

    - name: Display name.
    - value: Stored value.
    - status: Current state.
    """

    name: str
    value: int
    status: str
'''

    assert DataclassAttributesRule().analyse(make_unit(src), default_ctx()) == []


def test_min_fields_option_can_raise_threshold():
    """Report nothing for an undocumented three-field dataclass when ``min_fields`` is 4."""
    src = """\
from dataclasses import dataclass

@dataclass
class Payload:
    name: str
    value: int
    status: str
"""
    rule = DataclassAttributesRule()
    ctx = RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(options={"min_fields": 4})}),
    )

    assert rule.analyse(make_unit(src), ctx) == []


def test_require_all_fields_reports_partial_attribute_section():
    """Report the two undocumented fields once when ``require_all_fields`` is set and the section covers one field."""
    src = '''\
from dataclasses import dataclass

@dataclass
class Payload:
    """Transport payload.

    Attributes:
        name: Display name.
    """

    name: str
    value: int
    status: str
'''
    rule = DataclassAttributesRule()
    ctx = RuleContext(
        project_root="/",
        config=AnalysisConfig(rules={rule.definition().id: RuleSettings(options={"require_all_fields": True})}),
    )

    findings = rule.analyse(make_unit(src), ctx)

    assert len(findings) == 1
    assert findings[0].metadata["documentedFields"] == ["name"]
    assert findings[0].metadata["missingFields"] == ["value", "status"]


def test_private_dataclass_is_skipped():
    """Report nothing for an undocumented private dataclass."""
    src = """\
from dataclasses import dataclass

@dataclass
class _Payload:
    name: str
    value: int
    status: str
"""

    assert DataclassAttributesRule().analyse(make_unit(src), default_ctx()) == []
