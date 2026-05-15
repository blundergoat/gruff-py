import json
import re

from gruff.command.dashboard_page_renderer import DashboardPageRenderer


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


def test_dashboard_html_renders_escaped_controls_and_iframe_shell():
    html = DashboardPageRenderer().dashboard_html(_state())

    assert html.startswith("<!DOCTYPE html>")
    assert 'id="controls-toggle"' in html
    assert "&#9881;" in html
    assert 'id="controls-panel"' in html
    assert "&times;" in html
    assert 'id="report-frame"' in html
    assert 'value="/tmp/gruff &lt;root&gt;"' in html
    assert 'value=".gruff &quot;quoted&quot;.yaml"' in html
    assert '<option value="warning" selected>warning</option>' in html
    assert 'name="noConfig" value="1" checked' in html
    assert 'name="reportInteractive" value="1" checked' in html
    assert "baseline" not in html.lower()
    assert "mutation" not in html.lower()


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


def test_inject_dashboard_metadata_embeds_valid_html_safe_json_payload():
    html = DashboardPageRenderer().inject_dashboard_metadata(
        "<!doctype html><html><body><main>scan</main></body></html>",
        project_root='/tmp/<project>&"quoted"',
        command=["gruff", "analyse", "--format", "html", "path with spaces"],
        exit_code=2,
        duration_ms=345,
    )
    payload = _metadata_payload(html)

    assert '<body><script id="gruff-dashboard-meta"' in html
    assert "\\u003Cproject\\u003E\\u0026" in html
    assert payload["type"] == "gruff-scan-complete"
    assert payload["exitCode"] == 2
    assert payload["durationMs"] == 345
    assert payload["projectRoot"] == '/tmp/<project>&"quoted"'
    assert payload["command"] == "gruff analyse --format html 'path with spaces'"


def _metadata_payload(html: str) -> dict[str, object]:
    match = re.search(
        r'<script id="gruff-dashboard-meta" type="application/json">(?P<payload>.*?)</script>',
        html,
    )
    assert match is not None
    payload = json.loads(match.group("payload"))
    assert isinstance(payload, dict)
    return payload
