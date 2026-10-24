from dataclasses import replace

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings, SeverityThreshold
from gruffpy.finding.severity import Severity
from gruffpy.rule.context import RuleContext
from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.test_quality.test_function_too_long_rule import TestFunctionTooLongRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def _ctx(threshold: int = 100) -> RuleContext:
    rule = TestFunctionTooLongRule()
    config = AnalysisConfig(
        rules={
            rule.definition().id: RuleSettings(
                enabled=True,
                severity_threshold=SeverityThreshold(threshold, Severity.ERROR),
            ),
        }
    )
    return RuleContext(project_root="/", config=config)


def test_short_test_skipped():
    src = "def test_foo():\n    assert 1 + 1 == 2\n"
    assert TestFunctionTooLongRule().analyse(make_unit(src), default_ctx()) == []


def test_under_default_threshold_emits_no_finding():
    body = "\n".join(f"    x{i} = {i}" for i in range(60))
    src = f"def test_foo():\n{body}\n    assert True\n"
    assert TestFunctionTooLongRule().analyse(make_unit(src), default_ctx()) == []


def test_above_default_threshold_fires_at_error_severity():
    body = "\n".join(f"    x{i} = {i}" for i in range(120))
    src = f"def test_foo():\n{body}\n    assert True\n"
    findings = TestFunctionTooLongRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["lines"] > 100
    assert finding.metadata["threshold"] == 100
    assert finding.metadata["thresholdType"] == "error"


def test_custom_threshold_above_emits_error():
    body = "\n".join(f"    x{i} = {i}" for i in range(75))
    src = f"def test_foo():\n{body}\n    assert True\n"
    findings = TestFunctionTooLongRule().analyse(make_unit(src), _ctx(threshold=50))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.ERROR
    assert finding.metadata["thresholdType"] == "error"


def test_documented_test_is_measured_by_its_code_lines():
    notes = "\n".join(f"    Note {i}." for i in range(20))
    doc = f'    """Checks every value.\n\n{notes}\n    """'
    comments = "\n".join(f"    # Step {i}." for i in range(20))
    body = "\n".join(f"    x{i} = {i}" for i in range(95))
    src = f"def test_foo():\n{doc}\n{comments}\n{body}\n    assert True\n"
    assert TestFunctionTooLongRule().analyse(make_unit(src), default_ctx()) == []


def _response_snapshot_source() -> str:
    """Build the observed response check with a long literal expected snapshot.

    Returns:
        Test source whose expected data crosses the physical code-line limit.
    """
    fields = "\n".join(f'        "field_{index}": {index},' for index in range(120))
    return (
        "from inline_snapshot import snapshot\n\n"
        "def test_response():\n"
        '    response = client.get("/openapi.json")\n'
        "    assert response.status_code == 200, response.text\n"
        "    assert response.json() == snapshot({\n"
        f"{fields}\n"
        "    })\n"
    )


@pytest.mark.parametrize(
    ("snapshot_name", "documented"),
    [
        pytest.param("snapshot", False, id="literal-get-response"),
        pytest.param("expected", False, id="import-alias"),
        pytest.param("snapshot", True, id="documented-snapshot"),
    ],
)
def test_inline_response_snapshot_needs_no_length_finding(snapshot_name: str, documented: bool) -> None:
    """Keep a single response snapshot quiet when expected data supplies its size.

    Args:
        snapshot_name: Direct or explicitly aliased inline_snapshot import.
        documented: Whether a docstring precedes the same response check.
    """
    source = _response_snapshot_source()
    if snapshot_name != "snapshot":
        source = source.replace("import snapshot", f"import snapshot as {snapshot_name}")
        source = source.replace("snapshot({", f"{snapshot_name}({{")
    if documented:
        source = source.replace("def test_response():\n", 'def test_response():\n    """Check the response schema."""\n')
    assert TestFunctionTooLongRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    ("before", "after"),
    [
        pytest.param("from inline_snapshot import snapshot", "from unrelated_helper import snapshot", id="unrelated-helper"),
        pytest.param("def test_response():", "snapshot = replacement\n\ndef test_response():", id="module-rebinding"),
        pytest.param("def test_response():", "def test_response(snapshot):", id="parameter-shadow"),
        pytest.param("def test_response():", "from other_helpers import *\n\ndef test_response():", id="star-import"),
        pytest.param('client.get("/openapi.json")', "client.get(endpoint)", id="computed-request-url"),
        pytest.param('"field_0": 0,', '"field_0": make_value(),', id="computed-snapshot-value"),
        pytest.param("    assert response.json()", "    response.close()\n    assert response.json()", id="extra-operation"),
        pytest.param(
            "    assert response.status_code == 200, response.text",
            "    if response.status_code != 200:\n        assert False",
            id="conditional-status",
        ),
    ],
)
def test_snapshot_exemption_retains_other_long_test_shapes(before: str, after: str) -> None:
    """Retain findings for uncertain snapshot bindings or additional test behavior.

    Args:
        before: Exact source fragment in the observed snapshot-only shape.
        after: Replacement introducing the distinct retained behavior.
    """
    source = _response_snapshot_source()
    assert before in source
    findings = TestFunctionTooLongRule().analyse(make_unit(source.replace(before, after, 1)), default_ctx())
    assert len(findings) == 1
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["lines"] > 100
    assert findings[0].metadata["threshold"] == 100


def test_default_off_and_explicit_enable_preserve_the_repair() -> None:
    """Keep long tests opt-in while retaining the snapshot exemption when enabled."""
    registry = RuleRegistry.defaults()
    body = "\n".join(f"    value_{index} = {index}" for index in range(120))
    units = [make_unit(f"def test_long():\n{body}\n    assert True\n"), make_unit(_response_snapshot_source())]
    context = default_ctx()
    assert not TestFunctionTooLongRule().definition().default_enabled
    assert not any(finding.rule_id == TestFunctionTooLongRule.ID for finding in registry.analyse(units, context))
    settings = replace(context.config.rule_settings(TestFunctionTooLongRule.ID), enabled=True)
    enabled_context = replace(context, config=context.config.with_rule_settings(TestFunctionTooLongRule.ID, settings))
    findings = [finding for finding in registry.analyse(units, enabled_context) if finding.rule_id == TestFunctionTooLongRule.ID]
    assert len(findings) == 1
    assert findings[0].symbol == "test_long"
    assert findings[0].severity == Severity.ERROR
    assert findings[0].metadata["threshold"] == 100
