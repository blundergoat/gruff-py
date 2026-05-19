import json
import re

from gruffpy.command.dashboard_page_renderer import DashboardPageRenderer


def _state(**overrides: str) -> dict[str, str]:
    state = {
        "project": "/tmp/gruff <root>",
        "paths": 'src "tests"',
        "failOn": "warning",
        "config": '.gruff "quoted".yaml',
        "noConfig": "1",
        "includeIgnored": "0",
        "reportInteractive": "1",
    }
    state.update(overrides)
    return state


_EXPECTED_DASHBOARD_HTML_SUBSTRINGS = (
    'id="controls-toggle"',
    "&#9881;",
    'id="controls-panel"',
    "&times;",
    'id="report-frame"',
    'value="/tmp/gruff &lt;root&gt;"',
    'value=".gruff &quot;quoted&quot;.yaml"',
    '<option value="warning" selected>warning</option>',
    'name="noConfig" value="1" checked',
    'name="reportInteractive" value="1" checked',
)
_UNEXPECTED_DASHBOARD_HTML_SUBSTRINGS_LOWERCASE = ("baseline", "mutation")


def test_dashboard_html_renders_with_doctype_and_required_substrings():
    html = DashboardPageRenderer().dashboard_html(_state())
    assert html.startswith("<!DOCTYPE html>")
    missing = [s for s in _EXPECTED_DASHBOARD_HTML_SUBSTRINGS if s not in html]
    assert not missing, f"missing substrings in dashboard html: {missing}"


def test_dashboard_html_omits_unimplemented_feature_words():
    html = DashboardPageRenderer().dashboard_html(_state()).lower()
    present = [s for s in _UNEXPECTED_DASHBOARD_HTML_SUBSTRINGS_LOWERCASE if s in html]
    assert not present, f"unexpected words leaked into dashboard html: {present}"


def test_loading_frame_and_error_html_escape_untrusted_text():
    renderer = DashboardPageRenderer()

    loading = renderer.loading_frame()
    error = renderer.error_html(
        'Failed <scan> "now"',
        "line & detail\nsecond line",
        exit_code=7,
        duration_ms=123,
    )

    assert "Ready to scan." in loading
    assert "Failed &lt;scan&gt; &quot;now&quot;" in error
    assert "line &amp; detail\nsecond line" in error
    assert "Exit code: 7 - Duration: 123ms" in error


def test_inject_dashboard_metadata_embeds_html_safe_script_block():
    html = DashboardPageRenderer().inject_dashboard_metadata(
        "<!doctype html><html><body><main>scan</main></body></html>",
        project_root='/tmp/<project>&"quoted"',
        command=["gruff-py", "analyse", "--format", "html", "path with spaces"],
        exit_code=2,
        duration_ms=345,
    )
    assert '<body><script id="gruff-dashboard-meta"' in html
    assert "\\u003Cproject\\u003E\\u0026" in html


def test_inject_dashboard_metadata_payload_records_scan_provenance():
    html = DashboardPageRenderer().inject_dashboard_metadata(
        "<!doctype html><html><body><main>scan</main></body></html>",
        project_root='/tmp/<project>&"quoted"',
        command=["gruff-py", "analyse", "--format", "html", "path with spaces"],
        exit_code=2,
        duration_ms=345,
    )
    payload = _metadata_payload(html)
    assert payload == {
        "type": "gruff-scan-complete",
        "exitCode": 2,
        "durationMs": 345,
        "projectRoot": '/tmp/<project>&"quoted"',
        "command": "gruff-py analyse --format html 'path with spaces'",
    }


def _metadata_payload(html: str) -> dict[str, object]:
    match = re.search(
        r'<script id="gruff-dashboard-meta" type="application/json">(?P<payload>.*?)</script>',
        html,
    )
    assert match is not None
    payload = json.loads(match.group("payload"))
    assert isinstance(payload, dict)
    return payload
