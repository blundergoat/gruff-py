"""Self-contained local dashboard shell renderer."""

# The CSS/JS is intentionally inline to match gruff-php's no-assets dashboard.
# ruff: noqa: E501

import html
import json
import shlex
from urllib.parse import urlencode

from gruffpy.version import TOOL_NAME


class DashboardPageRenderer:
    """Builds the self-contained HTML shell served by the local dashboard."""

    def dashboard_html(self, state: dict[str, str]) -> str:
        """Return the dashboard shell page seeded with *state* in the form fields.

        Inlines CSS and JS so the shell is fully self-contained — no external
        asset fetches, mirroring gruff-php's no-assets dashboard.

        Args:
            state: Query-shaped state dict (from :meth:`DashboardState.to_query`).

        Returns:
            Single complete HTML document.
        """
        scan_url = "/scan?" + urlencode(state)
        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
            f"<title>{TOOL_NAME} dashboard</title><style>{_DASHBOARD_CSS}</style></head><body>"
            '<button type="button" id="controls-toggle" class="controls-toggle" '
            'aria-haspopup="dialog" aria-expanded="false" aria-controls="controls-panel" '
            'title="Dashboard controls">&#9881;</button>'
            '<section id="controls-panel" class="controls-panel" role="dialog" '
            'aria-label="Dashboard controls" hidden>'
            '<div class="panel-head"><div><strong>Dashboard controls</strong>'
            "<span>local scan settings</span></div>"
            '<button type="button" id="controls-close" aria-label="Close dashboard controls">&times;</button></div>'
            '<div class="scan-summary" aria-label="Scan status">'
            '<div class="scan-status"><span>Status</span><strong id="scan-status" '
            'aria-live="polite">Ready</strong></div>'
            '<div class="scan-command"><span>Last scan</span><div class="scan-meta-line">'
            '<code id="scan-meta">Not run</code><button type="button" id="copy-scan-meta">'
            "Copy</button></div></div></div>"
            '<form id="scan-form" method="get" action="/">'
            '<div class="field-stack">'
            f"{_field('Project root', 'project', state['project'])}"
            f"{_field('Paths', 'paths', state['paths'])}"
            "</div>"
            '<div class="field-grid">'
            f"{_field('Config path', 'config', state['config'], '.gruff-py.yaml')}"
            '<label>Fail on<select name="failOn">'
            f"{_option('none', state['failOn'])}"
            f"{_option('advisory', state['failOn'])}"
            f"{_option('warning', state['failOn'])}"
            f"{_option('error', state['failOn'])}"
            "</select></label></div>"
            '<div class="option-grid">'
            f"{_checkbox('noConfig', 'skip config', state['noConfig'])}"
            f"{_checkbox('includeIgnored', 'include ignored', state['includeIgnored'])}"
            f"{_checkbox('reportInteractive', 'interactive findings', state['reportInteractive'])}"
            "</div>"
            '<div class="panel-actions"><button type="button" id="refresh">Refresh</button>'
            '<button type="submit" id="run-scan">Run scan</button></div></form></section>'
            f'<iframe id="report-frame" title="gruff-py report" '
            f'data-initial-src="{_esc_attr(scan_url)}" '
            f'srcdoc="{_esc_attr(self.loading_frame())}"></iframe>'
            f"<script>{_DASHBOARD_JS}</script></body></html>"
        )

    def inject_dashboard_metadata(
        self,
        html_text: str,
        *,
        project_root: str,
        command: list[str],
        exit_code: int,
        duration_ms: int,
    ) -> str:
        """Splice a JSON-payload ``<script>`` + post-message bridge into the scan iframe.

        The injected script reads the JSON tag and forwards it to
        ``window.parent`` so the dashboard shell can show exit-code and
        timing metadata without rescanning. Falls back to prepending the
        metadata when no ``<body>`` tag is present.

        Args:
            html_text: The freshly rendered HTML report.
            project_root: Resolved project root (for display in the shell).
            command: Command-line argv that produced this scan.
            exit_code: ``run_analysis`` exit code (0 = clean, 1 = findings, 2 = errors).
            duration_ms: Wall-clock duration of the scan.

        Returns:
            The original HTML with the metadata script injected at body open.
        """
        payload = _json_script_payload(
            {
                "type": "gruff-scan-complete",
                "exitCode": exit_code,
                "durationMs": duration_ms,
                "projectRoot": project_root,
                "command": display_command(command),
            }
        )
        metadata = (
            '<script id="gruff-dashboard-meta" type="application/json">'
            f"{payload}</script>"
            '<script>(()=>{const el=document.getElementById("gruff-dashboard-meta");'
            "if(window.parent&&el){window.parent.postMessage(JSON.parse(el.textContent),"
            "window.location.origin);}})();</script>"
        )
        if "<body>" in html_text:
            return html_text.replace("<body>", "<body>" + metadata, 1)
        return metadata + html_text

    def error_html(
        self,
        message: str,
        detail: str,
        *,
        exit_code: int,
        duration_ms: int,
    ) -> str:
        """Return a minimal HTML error page surfaced inside the dashboard iframe on scan failure.

        Args:
            message: One-line user-facing summary.
            detail: Longer free-form context (typically the exception ``str``).
            exit_code: Numeric exit code to display next to the message.
            duration_ms: Wall-clock duration before the error surfaced.

        Returns:
            Self-contained HTML document with the error styled to match the shell.
        """
        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
            f"<title>{TOOL_NAME} dashboard error</title>"
            "<style>body{font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"
            "monospace;background:#161412;color:#f3e9d2;padding:32px}"
            "main{max-width:920px;margin:0 auto}pre{white-space:pre-wrap;background:#0d0c0a;"
            "border:1px solid #2a2622;padding:16px;overflow:auto}</style></head><body><main>"
            f"<h1>{TOOL_NAME} dashboard</h1>"
            f"<p>{_esc(message)}</p>"
            f"<p>Exit code: {exit_code} - Duration: {duration_ms}ms</p>"
            f"<pre>{_esc(detail)}</pre>"
            "</main></body></html>"
        )

    def loading_frame(self) -> str:
        """Return the ``Ready to scan.`` placeholder injected via the iframe ``srcdoc``.

        Shown until the first ``/scan`` response loads — keeps the dashboard
        visually consistent on initial paint.

        Returns:
            Self-contained HTML document acting as a loading placeholder.
        """
        return (
            '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
            "<style>body{margin:0;background:#0d0c0a;color:#f3e9d2;font:14px "
            "ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;display:grid;"
            "place-items:center;min-height:100vh}</style></head><body>Ready to scan.</body></html>"
        )


def display_command(command: list[str]) -> str:
    """Render an argv list as a copy-pasteable shell command string.

    Each part is run through :func:`shlex.quote` so whitespace and quotes
    survive a round-trip back into a real shell.

    Args:
        command: argv list as produced by ``_display_command_for``.

    Returns:
        Single line shell-quoted command string.
    """
    return " ".join(shlex.quote(part) for part in command)


def _field(label: str, name: str, value: str, placeholder: str = "") -> str:
    return (
        f"<label>{_esc(label)}"
        f'<input name="{_esc_attr(name)}" value="{_esc_attr(value)}" '
        f'placeholder="{_esc_attr(placeholder)}"></label>'
    )


def _option(value: str, selected: str, label: str | None = None) -> str:
    is_selected = " selected" if value == selected else ""
    return (
        f'<option value="{_esc_attr(value)}"{is_selected}>'
        f"{_esc(label if label is not None else value)}</option>"
    )


def _checkbox(name: str, label: str, value: str) -> str:
    checked = " checked" if value == "1" else ""
    return (
        f'<label class="check"><input type="checkbox" name="{_esc_attr(name)}" '
        f'value="1"{checked}><span>{_esc(label)}</span></label>'
    )


def _json_script_payload(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    return encoded.replace("<", "\\u003C").replace(">", "\\u003E").replace("&", "\\u0026")


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _esc_attr(value: str) -> str:
    return html.escape(value, quote=True)


_DASHBOARD_JS = r"""
const form=document.getElementById('scan-form');const frame=document.getElementById('report-frame');const refresh=document.getElementById('refresh');const runButton=document.getElementById('run-scan');const status=document.getElementById('scan-status');const scanMeta=document.getElementById('scan-meta');const copyScanMeta=document.getElementById('copy-scan-meta');const toggle=document.getElementById('controls-toggle');const panel=document.getElementById('controls-panel');const close=document.getElementById('controls-close');let scans=0;let busyTimer=null;let busyStarted=0;function params(){return new URLSearchParams(new FormData(form));}function setOpen(open){panel.hidden=!open;toggle.setAttribute('aria-expanded',open?'true':'false');if(open){form.elements.project.focus();}}function stopBusyTimer(){if(busyTimer!==null){clearInterval(busyTimer);busyTimer=null;}}function renderBusy(){status.textContent='Scanning... '+Math.floor((Date.now()-busyStarted)/1000)+'s';}function setBusy(busy){refresh.disabled=busy;runButton.disabled=busy;toggle.classList.toggle('busy',busy);toggle.setAttribute('aria-label',busy?'Scanning':'Dashboard controls');stopBusyTimer();if(busy){busyStarted=Date.now();renderBusy();busyTimer=setInterval(renderBusy,1000);}else{status.textContent='Scan loaded';}}function updateMeta(data){if(!data||data.type!=='gruff-scan-complete'){return;}const exit=Number.isInteger(data.exitCode)?data.exitCode:'?';const duration=Number.isInteger(data.durationMs)?data.durationMs+'ms':'duration n/a';const command=typeof data.command==='string'?data.command:'';scanMeta.textContent='exit '+exit+' - '+duration+(command===''?'':' - '+command);}async function copyMeta(){const text=scanMeta.textContent||'';try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);}else{const range=document.createRange();range.selectNodeContents(scanMeta);const selection=window.getSelection();if(selection){selection.removeAllRanges();selection.addRange(range);document.execCommand('copy');selection.removeAllRanges();}}copyScanMeta.textContent='Copied';setTimeout(()=>{copyScanMeta.textContent='Copy';},1200);}catch(error){copyScanMeta.textContent='Copy failed';setTimeout(()=>{copyScanMeta.textContent='Copy';},1200);}}function run(){const qs=params();const visible=new URLSearchParams(qs);qs.set('_run',Date.now().toString()+'-'+(++scans));setBusy(true);frame.removeAttribute('srcdoc');frame.src='/scan?'+qs.toString();history.replaceState(null,'','/?'+visible.toString());}toggle.addEventListener('click',event=>{event.stopPropagation();setOpen(panel.hidden);});close.addEventListener('click',()=>setOpen(false));document.addEventListener('click',event=>{if(!panel.hidden&&!panel.contains(event.target)&&event.target!==toggle){setOpen(false);}});document.addEventListener('keydown',event=>{if(event.key==='Escape'){setOpen(false);}});window.addEventListener('message',event=>{if(event.origin!==window.location.origin)return;updateMeta(event.data);});frame.addEventListener('load',()=>{setBusy(false);try{const el=frame.contentDocument&&frame.contentDocument.getElementById('gruff-dashboard-meta');if(el){updateMeta(JSON.parse(el.textContent||'{}'));}}catch(error){}});form.addEventListener('submit',event=>{event.preventDefault();run();});refresh.addEventListener('click',run);copyScanMeta.addEventListener('click',copyMeta);setTimeout(run,0);
"""

_DASHBOARD_CSS = r"""
:root{color-scheme:dark;--paper:#f3e9d2;--ink:#11100e;--panel:#1b1815;--field:#0d0c0a;--line:#332d27;--muted:#b5ab94;--accent:#e85d04;--accent-dark:#120f0d}*{box-sizing:border-box}body{margin:0;background:var(--ink);color:var(--paper);font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;height:100vh;overflow:hidden}.controls-toggle{position:fixed;top:14px;right:24px;z-index:20;width:44px;height:44px;border:1px solid var(--accent);border-radius:6px;background:var(--accent);color:var(--accent-dark);font:700 24px/1 ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;cursor:pointer;display:grid;place-items:center;box-shadow:0 4px 14px rgba(0,0,0,.45)}.controls-toggle.busy:after{content:'';position:absolute;right:5px;bottom:5px;width:9px;height:9px;border-radius:50%;background:var(--paper);border:1px solid var(--accent-dark)}.controls-panel{position:fixed;top:66px;right:24px;z-index:21;width:min(560px,calc(100vw - 48px));max-height:calc(100vh - 86px);overflow:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px;box-shadow:0 18px 50px rgba(0,0,0,.45);padding:18px}.panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;padding-bottom:14px;border-bottom:1px solid var(--line)}.panel-head strong{display:block;font:italic 30px Georgia,Iowan Old Style,serif;letter-spacing:0}.panel-head span{display:block;margin-top:4px;color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.18em}.panel-head button{width:44px;height:44px;padding:0;border:1px solid var(--line);background:var(--field);color:var(--paper);font-size:24px;line-height:1}.scan-summary{display:grid;grid-template-columns:minmax(108px,auto) 1fr;gap:10px 18px;margin:18px 0 16px;padding:14px 16px;background:var(--field);border:1px solid var(--line);font-size:12px}.scan-status,.scan-command{display:contents}.scan-summary span{color:var(--muted);text-transform:uppercase;letter-spacing:.12em}.scan-summary strong,.scan-summary code{min-width:0;color:var(--paper);font:13px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}.scan-meta-line{min-width:0;display:grid;grid-template-columns:1fr auto;gap:10px;align-items:start}.scan-summary code{white-space:normal;overflow:visible;overflow-wrap:anywhere;word-break:break-word}.scan-meta-line button{align-self:start;min-width:68px;padding:7px 9px;font-size:11px}form{display:grid;grid-template-columns:1fr;gap:14px}.field-stack,.field-grid,.option-grid{display:grid;gap:12px}.field-grid{grid-template-columns:1fr 1fr}.option-grid{grid-template-columns:repeat(3,minmax(0,1fr));padding:4px 0}label{display:flex;flex-direction:column;gap:7px;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}.check{display:grid;grid-template-columns:auto 1fr;align-items:center;gap:10px;text-transform:none;letter-spacing:0;font-size:12px;color:var(--paper);line-height:1.35}.check span{min-width:0}input,select{width:100%;min-height:46px;border:1px solid var(--line);background:var(--field);color:var(--paper);padding:10px 12px;font:14px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace}input[type=checkbox]{width:18px;min-height:18px;height:18px;margin:0;accent-color:var(--accent)}button{border:1px solid var(--accent);background:var(--accent);color:var(--accent-dark);padding:12px 14px;font:700 13px ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;cursor:pointer}button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--paper);outline-offset:2px}button:disabled{opacity:.6;cursor:wait}.panel-actions{display:grid;grid-template-columns:1fr 1fr;gap:12px;padding-top:2px}.panel-actions button{min-height:48px}iframe{width:100vw;height:100vh;border:0;background:var(--field);display:block}@media(max-width:700px){.controls-toggle{top:10px;right:18px}.controls-panel{top:60px;right:18px;width:calc(100vw - 36px);padding:16px}.field-grid,.option-grid,.scan-summary,.scan-meta-line{grid-template-columns:1fr}.panel-head strong{font-size:28px}}
"""
