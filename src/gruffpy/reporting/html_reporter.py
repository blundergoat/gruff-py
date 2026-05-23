"""Self-contained gruff HTML report renderer."""

# The inline CSS/JS intentionally mirrors gruff-php's dependency-free reporter
# style, so long asset strings are kept in this file instead of split across
# separate static assets.
# ruff: noqa: E501 - inline CSS/JS stays self-contained for reports

import html
from pathlib import Path
from urllib.parse import quote

from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.schema import ANALYSIS_SCHEMA_VERSION
from gruffpy.finding.finding import Finding
from gruffpy.scoring.file_score import FileScore
from gruffpy.scoring.pillar_score import PillarScore
from gruffpy.version import TOOL_NAME


class HtmlReporter:
    """Render an analysis report as a single-file HTML document with optional interactive filters."""

    def __init__(
        self,
        project_root: str = "",
        editor_link: str = "none",
        interactive: bool = False,
    ) -> None:
        self.project_root = project_root
        self.editor_link = editor_link
        self.interactive = interactive

    def render(self, report: AnalysisReport) -> str:
        """Render *report* as the standalone single-file HTML inspection report.

        Sections: masthead, optional diagnostics block, verdict (grade
        stamp + severity counts), per-pillar grade cards, top-offender
        table, cyclomatic-complexity histogram, finding list, and footer.
        When ``interactive=True``, the finding section also gets a filter
        toolbar backed by inline ES modules.

        Args:
            report: Fully-populated analysis report.

        Returns:
            Complete single-file HTML document (no external assets).
        """
        score = report.score
        grade = score.composite.letter if score is not None else "n/a"
        numeric_score = f"{score.composite.score:.2f} / 100" if score is not None else "n/a"
        counts = report.finding_counts()
        title = f"gruff-py inspection report - {grade}"
        script = (
            f'<script type="module">{_INTERACTIVE_SCRIPT}</script>\n' if self.interactive else ""
        )

        return (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n'
            "<head>\n"
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
            f"<title>{_esc(title)}</title>\n"
            f"<style>{self._css(bool(report.diagnostics))}</style>\n"
            "</head>\n"
            "<body>\n"
            '<div class="paper"><span class="corner-tr"></span><span class="corner-bl"></span>'
            f"{self._masthead(report)}"
            f"{self._diagnostics(report)}"
            f"{self._verdict(grade, numeric_score, counts, report)}"
            f"{self._pillars(report)}"
            f"{self._offenders(report)}"
            f"{self._distribution(report)}"
            f"{self._findings(report)}"
            f"{self._footer(report)}"
            "</div>\n"
            f"{script}"
            "</body>\n"
            "</html>\n"
        )

    def _masthead(self, report: AnalysisReport) -> str:
        paths = report.requested_paths or (".",)
        return (
            '<header class="masthead">'
            '<div class="brand"><div class="wordmark">gruff</div>'
            '<div class="tagline">python code quality - inspection report</div></div>'
            '<div class="meta">'
            f"{_meta_row('paths', ', '.join(paths))}"
            f"{_meta_row('scope', report.score.scope if report.score is not None else 'full-project')}"
            f"{_meta_row('format', report.format)}"
            f"{_meta_row('fail', report.fail_on)}"
            f'<div class="inspection-id">{_esc(TOOL_NAME + " " + report.tool_version)}</div>'
            "</div></header>"
        )

    def _diagnostics(self, report: AnalysisReport) -> str:
        if not report.diagnostics:
            return ""
        rows = "".join(_diagnostic_row(diagnostic) for diagnostic in report.diagnostics)
        return (
            '<section class="diagnostics"><h2 class="section-head">diagnostics '
            '<span class="aside">run messages</span></h2>'
            f'<div class="diagnostic-list">{rows}</div></section>'
        )

    def _verdict(
        self,
        grade: str,
        numeric_score: str,
        counts: dict[str, int],
        report: AnalysisReport,
    ) -> str:
        summary = _verdict_summary(report, counts)
        return (
            '<section class="verdict">'
            '<div class="grade-stamp">'
            f'<div class="grade-letter">{_esc(grade)}</div>'
            f'<div class="grade-score">{_esc(numeric_score)}</div>'
            "</div>"
            '<div class="verdict-body">'
            f'<div class="verdict-headline">Inspection complete.<br><em>{_esc(summary)}</em></div>'
            '<div class="verdict-stats">'
            f"{_stat(str(counts['total']), 'findings', '')}"
            f"{_stat(str(counts['error']), 'errors', 'fail')}"
            f"{_stat(str(counts['warning']), 'warnings', 'warn')}"
            f"{_stat(str(counts['advisory']), 'advisories', 'note')}"
            "</div></div></section>"
        )

    def _pillars(self, report: AnalysisReport) -> str:
        items = () if report.score is None else report.score.pillars
        cards = "".join(
            _pillar_card(pillar) for pillar in items if pillar.pillar.lower() != "mutation"
        )
        return (
            '<section class="pillars"><h2 class="section-head">pillar grades '
            '<span class="aside">weighted composite</span></h2>'
            f'<div class="pillar-grid">{cards}</div></section>'
        )

    def _offenders(self, report: AnalysisReport) -> str:
        items = () if report.score is None else report.score.top_offenders
        rows = "".join(self._offender_row(item) for item in items)
        if not rows:
            rows = '<tr><td colspan="6">No offenders found.</td></tr>'
        return (
            '<section class="offenders"><h2 class="section-head">top offenders '
            '<span class="aside">sorted by score</span></h2>'
            '<table class="offender-list"><thead><tr>'
            '<th scope="col">file</th><th scope="col" class="num">cyclo</th>'
            '<th scope="col" class="num">cognit.</th><th scope="col" class="num">LOC</th>'
            '<th scope="col" class="num">findings</th><th scope="col" class="num">grade</th>'
            f"</tr></thead><tbody>{rows}</tbody></table></section>"
        )

    def _distribution(self, report: AnalysisReport) -> str:
        distribution = {} if report.score is None else report.score.complexity_distribution
        max_count = max(1, *distribution.values())
        bars = []
        axis = []
        for label, count in distribution.items():
            height = max(4, round((count / max_count) * 100))
            class_name = (
                " fail" if label in {"16-20", "21+"} else " warn" if label == "11-15" else ""
            )
            bars.append(
                f'<div class="bar{class_name}" style="height:{height}%;">'
                f'<span class="count">{count}</span></div>'
            )
            axis.append(f"<span>{_esc(label)}</span>")
        return (
            '<section class="chart-section"><h2 class="section-head">distribution '
            '<span class="aside">cyclomatic complexity</span></h2>'
            f'<p class="chart-summary">{_esc(_cyclomatic_summary(distribution))}</p>'
            '<div class="chart-card"><div class="title">cyclomatic complexity - flagged functions</div>'
            f'<div class="histogram">{"".join(bars)}</div>'
            f'<div class="histogram-axis">{"".join(axis)}</div></div></section>'
        )

    def _findings(self, report: AnalysisReport) -> str:
        filters = self._finding_filters(report) if self.interactive else ""
        attributes = " data-findings-list" if self.interactive else ""
        rows = "".join(self._finding_row(finding) for finding in report.findings)
        if not rows:
            rows = '<div class="empty">No findings.</div>'
        return (
            '<section class="findings">'
            f'<h2 class="section-head">flagged findings <span class="aside">{len(report.findings)} shown</span></h2>'
            f"{filters}"
            f'<div class="findings-list"{attributes}>{rows}</div></section>'
        )

    def _footer(self, report: AnalysisReport) -> str:
        return (
            '<footer class="footer">'
            f'<div class="left">gruff-py - v{_esc(report.tool_version)}</div>'
            '<div class="center">strong opinions, opinionated defaults</div>'
            f'<div class="right">schema - {_esc(ANALYSIS_SCHEMA_VERSION)}</div>'
            "</footer>"
        )

    def _offender_row(self, file_score: FileScore) -> str:
        grade = file_score.grade.letter.lower()
        return (
            "<tr>"
            f'<td class="file-path">{self._location_markup(file_score.file_path, None)}</td>'
            f'<td class="num">{_esc(_optional_int(file_score.max_cyclomatic))}</td>'
            f'<td class="num">{_esc(_optional_int(file_score.max_cognitive))}</td>'
            f'<td class="num">{_esc(_optional_int(file_score.max_lines))}</td>'
            f'<td class="num">{file_score.findings}</td>'
            f'<td class="num"><span class="grade-pill {grade}">{_esc(file_score.grade.letter)}</span></td>'
            "</tr>"
        )

    def _finding_row(self, finding: Finding) -> str:
        severity_class = {
            "error": "fail",
            "warning": "warn",
            "advisory": "note",
        }[finding.severity.value]
        attributes = ""
        if self.interactive:
            search = f"{finding.rule_id} {finding.message}"
            attributes = (
                f' data-severity="{_esc_attr(finding.severity.value)}"'
                f' data-pillar="{_esc_attr(finding.pillar.value)}"'
                f' data-file="{_esc_attr(finding.file_path)}"'
                f' data-rule="{_esc_attr(finding.rule_id)}"'
                f' data-search="{_esc_attr(search)}"'
            )
        return (
            f'<div class="finding"{attributes}>'
            f'<div class="severity {severity_class}">{_esc(finding.severity.value)}</div>'
            '<div class="finding-body">'
            f'<h3 class="rule">{_esc(finding.rule_id)}</h3>'
            f'<div class="msg">{_esc(finding.message)}</div>'
            f'<div class="loc"><code>{self._location_markup(finding.file_path, finding.line)}</code></div>'
            "</div>"
            f'<div class="points"><b>{_esc(finding.pillar.value)}</b></div>'
            "</div>"
        )

    def _location_markup(self, file_path: str, line: int | None) -> str:
        text = file_path if line is None else f"{file_path}:{line}"
        href = self._editor_href(file_path, line)
        location_attribute = f' data-path="{_esc_attr(text)}"'
        if href is not None:
            return (
                f'<a class="loc-link" href="{_esc_attr(href)}"{location_attribute}>{_esc(text)}</a>'
            )
        return f'<span class="loc-link" tabindex="0"{location_attribute}>{_esc(text)}</span>'

    def _editor_href(self, file_path: str, line: int | None) -> str | None:
        if self.editor_link == "none":
            return None
        absolute_path = self._absolute_path(file_path)
        if self.editor_link == "vscode":
            suffix = "" if line is None else f":{line}"
            return f"vscode://file{quote(absolute_path)}{suffix}"
        if self.editor_link == "phpstorm":
            suffix = "" if line is None else f"&line={line}"
            return f"phpstorm://open?file={quote(absolute_path)}{suffix}"
        return None

    def _absolute_path(self, file_path: str) -> str:
        if file_path.startswith("/"):
            return file_path
        root = self.project_root or str(Path.cwd())
        return str(Path(root) / file_path)

    def _finding_filters(self, report: AnalysisReport) -> str:
        pillars = sorted({finding.pillar.value for finding in report.findings})
        pillar_options = "".join(
            f'<option value="{_esc_attr(pillar)}">{_esc(pillar)}</option>' for pillar in pillars
        )
        pillar_size = max(2, min(6, len(pillars)))
        return (
            '<form class="finding-filters" data-finding-filters aria-label="Filter flagged findings">'
            '<div class="filter-grid">'
            '<label>Severity<select name="severity" multiple size="3">'
            '<option value="error">error</option><option value="warning">warning</option>'
            '<option value="advisory">advisory</option></select></label>'
            f'<label>Pillar<select name="pillar" multiple size="{pillar_size}">{pillar_options}</select></label>'
            '<label>Path<input name="path" type="search" autocomplete="off"></label>'
            '<label>Search<input name="q" type="search" autocomplete="off"></label>'
            "</div>"
            '<fieldset class="filter-group"><legend>Group by</legend>'
            '<label class="radio"><input type="radio" name="group" value="none" checked> none</label>'
            '<label class="radio"><input type="radio" name="group" value="file"> file</label>'
            '<label class="radio"><input type="radio" name="group" value="rule"> rule</label>'
            "</fieldset>"
            '<div class="filter-actions"><button type="button" data-clear-filters>Clear all</button>'
            f'<output class="filter-count" data-filter-count aria-live="polite">{len(report.findings)} of {len(report.findings)} findings shown.</output></div>'
            "</form>"
        )

    def _css(self, include_diagnostics: bool = False) -> str:
        css = _BASE_CSS
        if include_diagnostics:
            css += _DIAGNOSTICS_CSS
        if self.interactive:
            css += _FILTER_CSS
        return css


def _pillar_card(pillar: PillarScore) -> str:
    grade = pillar.grade.letter if pillar.grade is not None else "n/a"
    grade_class = grade[:1].lower() if grade else "n"
    score = "not applicable" if pillar.grade is None else f"{pillar.grade.score:.2f}"
    return (
        '<div class="pillar">'
        f'<div class="name">{_esc(pillar.pillar)}</div>'
        f'<div class="grade {grade_class}">{_esc(grade)}</div>'
        '<div class="breakdown">'
        f'<div class="row"><span class="key">score</span><span class="val">{_esc(score)}</span></div>'
        f'<div class="row"><span class="key">findings</span><span class="val">{pillar.findings}</span></div>'
        f'<div class="row"><span class="key">advisories</span><span class="val">{pillar.advisories}</span></div>'
        f'<div class="row"><span class="key">warnings</span><span class="val">{pillar.warnings}</span></div>'
        f'<div class="row"><span class="key">errors</span><span class="val">{pillar.errors}</span></div>'
        "</div></div>"
    )


def _meta_row(label: str, value: str) -> str:
    return (
        f'<div><span class="label">{_esc(label)}</span><span class="val">{_esc(value)}</span></div>'
    )


def _stat(number: str, label: str, class_name: str) -> str:
    return (
        f'<div class="stat"><div class="num {_esc_attr(class_name)}">{_esc(number)}</div>'
        f'<div class="lbl">{_esc(label)}</div></div>'
    )


def _diagnostic_row(diagnostic: RunDiagnostic) -> str:
    location = diagnostic.file_path or diagnostic.path
    if diagnostic.file_path is not None and diagnostic.line is not None:
        location = f"{diagnostic.file_path}:{diagnostic.line}"
    location_html = (
        "" if location is None else f'<span class="diagnostic-location">{_esc(location)}</span>'
    )
    return (
        '<div class="diagnostic">'
        f'<span class="diagnostic-type">{_esc(diagnostic.type)}</span>'
        f'<span class="diagnostic-message">{_esc(diagnostic.message)}</span>'
        f"{location_html}</div>"
    )


def _verdict_summary(report: AnalysisReport, counts: dict[str, int]) -> str:
    threshold_findings = counts["warning"] + counts["error"]
    if threshold_findings == 0:
        return "No warning or error findings flagged."
    pillars = {
        finding.pillar.value
        for finding in report.findings
        if finding.severity.value in {"warning", "error"}
    }
    finding_label = "finding" if threshold_findings == 1 else "findings"
    pillar_label = "pillar" if len(pillars) == 1 else "pillars"
    return (
        f"{threshold_findings} {finding_label} at warning or error severity "
        f"across {len(pillars)} {pillar_label}."
    )


def _cyclomatic_summary(distribution: dict[str, int]) -> str:
    moderate = distribution.get("11-15", 0)
    high = distribution.get("16-20", 0)
    severe = distribution.get("21+", 0)
    exceeds = moderate + high + severe
    method_label = "function" if exceeds == 1 else "functions"
    verb = "exceeds" if exceeds == 1 else "exceed"
    return (
        f"{exceeds} {method_label} {verb} CC 10 "
        f"({moderate} in 11-15, {high} in 16-20, {severe} at 21+)."
    )


def _optional_int(value: int | None) -> str:
    return "n/a" if value is None else str(value)


def _esc(value: str) -> str:
    return html.escape(value, quote=True)


def _esc_attr(value: str) -> str:
    return html.escape(value, quote=True)


_INTERACTIVE_SCRIPT = r"""
const form=document.querySelector('[data-finding-filters]');
const list=document.querySelector('[data-findings-list]');
if(form&&list){
const severitySelect=form.elements.severity;
const pillarSelect=form.elements.pillar;
const pathInput=form.elements.path;
const queryInput=form.elements.q;
const countOutput=form.querySelector('[data-filter-count]');
const clearButton=form.querySelector('[data-clear-filters]');
const severityOrder=Array.from(severitySelect.options).map(option=>option.value);
const pillarOrder=Array.from(pillarSelect.options).map(option=>option.value);
const groupOrder=['none','file','rule'];
const source=Array.from(list.querySelectorAll('.finding')).map((node,index)=>({index,node:node.cloneNode(true),severity:node.dataset.severity||'',pillar:node.dataset.pillar||'',file:node.dataset.file||'',rule:node.dataset.rule||'',search:(node.dataset.search||'').toLowerCase()}));
function selected(select){return Array.from(select.selectedOptions).map(option=>option.value);}
function setSelected(select,values){const allowed=new Set(values);Array.from(select.options).forEach(option=>{option.selected=allowed.has(option.value);});}
function radio(){const checked=form.querySelector('input[name="group"]:checked');return checked?checked.value:'none';}
function setRadio(value){const target=groupOrder.includes(value)?value:'none';const input=form.querySelector('input[name="group"][value="'+target+'"]');if(input){input.checked=true;}}
function parseList(value,allowed){if(!value){return [];}const allowedSet=new Set(allowed);return value.split(',').map(item=>item.trim()).filter(item=>allowedSet.has(item));}
function readHash(){const params=new URLSearchParams(window.location.hash.replace(/^#/,''));setSelected(severitySelect,parseList(params.get('severity'),severityOrder));setSelected(pillarSelect,parseList(params.get('pillar'),pillarOrder));pathInput.value=params.get('path')||'';queryInput.value=params.get('q')||'';setRadio(params.get('group')||'none');}
function filters(){return{severity:selected(severitySelect),pillar:selected(pillarSelect),path:pathInput.value.trim().toLowerCase(),q:queryInput.value.trim().toLowerCase(),group:radio()};}
function writeHash(){const state=filters();const parts=[];const orderedSeverity=severityOrder.filter(value=>state.severity.includes(value));const orderedPillar=pillarOrder.filter(value=>state.pillar.includes(value));if(orderedSeverity.length){parts.push('severity='+orderedSeverity.map(encodeURIComponent).join(','));}if(orderedPillar.length){parts.push('pillar='+orderedPillar.map(encodeURIComponent).join(','));}if(state.path){parts.push('path='+encodeURIComponent(state.path));}if(state.q){parts.push('q='+encodeURIComponent(state.q));}if(state.group!=='none'){parts.push('group='+encodeURIComponent(state.group));}const next=parts.length?'#'+parts.join('&'):window.location.pathname+window.location.search;history.replaceState(null,'',next);}
function matches(item,state){return(state.severity.length===0||state.severity.includes(item.severity))&&(state.pillar.length===0||state.pillar.includes(item.pillar))&&(state.path===''||item.file.toLowerCase().includes(state.path))&&(state.q===''||item.search.includes(state.q));}
function emptyNode(text){const node=document.createElement('div');node.className='empty';node.textContent=text;return node;}
function groupTitle(value){const node=document.createElement('h3');node.className='finding-group-title';node.textContent=value;return node;}
function render(){const state=filters();const visible=source.filter(item=>matches(item,state));list.replaceChildren();if(visible.length===0){list.append(emptyNode(source.length===0?'No findings.':'No findings match the active filters.'));}else if(state.group==='none'){visible.forEach(item=>list.append(item.node.cloneNode(true)));}else{const groups=new Map();visible.forEach(item=>{const key=state.group==='file'?item.file:item.rule;if(!groups.has(key)){groups.set(key,[]);}groups.get(key).push(item);});groups.forEach((items,key)=>{const section=document.createElement('section');section.className='finding-group';section.append(groupTitle(key));items.forEach(item=>section.append(item.node.cloneNode(true)));list.append(section);});}if(countOutput){countOutput.textContent=visible.length+' of '+source.length+' findings shown.';}}
function update(){writeHash();render();}
form.addEventListener('change',update);
form.addEventListener('input',event=>{if(event.target===pathInput||event.target===queryInput){update();}});
if(clearButton){clearButton.addEventListener('click',()=>{setSelected(severitySelect,[]);setSelected(pillarSelect,[]);pathInput.value='';queryInput.value='';setRadio('none');update();});}
window.addEventListener('hashchange',()=>{readHash();render();});
readHash();
render();
}
"""

_BASE_CSS = r"""
:root{--ink:#0d0c0a;--ink-2:#161412;--ink-3:#1f1c19;--paper:#f3e9d2;--paper-dim:#b5ab94;--paper-mute:#7d735f;--rule:#2a2622;--forge:#e85d04;--grade-a:#7fa15a;--grade-b:#b8b450;--grade-c:#d08c36;--grade-d:#c2552b;--grade-f:#8b2828;--advisory:#b5ab94;--serif:Georgia,'Iowan Old Style',serif;--mono:'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace}*{box-sizing:border-box;margin:0;padding:0}html{background:var(--ink);scrollbar-gutter:stable}body{font-family:var(--mono);color:var(--paper);background:var(--ink);min-height:100vh;line-height:1.5;font-size:14px;padding:48px 32px}.paper{max-width:1180px;margin:0 auto 24px;background:var(--ink-2);border:1px solid var(--rule);position:relative;padding:56px 64px 48px;scrollbar-gutter:stable}.corner-tr,.corner-bl,.paper:before,.paper:after{content:'';position:absolute;width:22px;height:22px;border:1px solid var(--forge)}.paper:before{top:12px;left:12px;border-right:0;border-bottom:0}.paper:after{bottom:12px;right:12px;border-left:0;border-top:0}.corner-tr{top:12px;right:12px;border-left:0;border-bottom:0}.corner-bl{bottom:12px;left:12px;border-right:0;border-top:0}.masthead{display:grid;grid-template-columns:1fr auto;gap:32px;padding-bottom:28px;border-bottom:1px solid var(--rule);align-items:end}.wordmark{font-family:var(--serif);font-weight:900;font-size:96px;line-height:.85;color:var(--paper);font-style:italic}.wordmark:after{content:'-py';color:var(--forge);font-style:normal;font-size:.45em;margin-left:.15em;vertical-align:super}.tagline{margin-top:12px;font-size:11px;letter-spacing:.24em;color:var(--paper-mute);text-transform:uppercase}.meta{text-align:right;font-size:11px;color:var(--paper-dim);line-height:1.9}.label{color:var(--paper-mute);text-transform:uppercase;letter-spacing:.16em;margin-right:8px}.val{color:var(--paper)}.inspection-id{margin-top:10px;color:var(--forge);font-weight:700;font-size:12px;letter-spacing:.1em}.section-head{font-size:11px;letter-spacing:.32em;color:var(--paper-mute);text-transform:uppercase;padding-bottom:16px;margin-bottom:20px;border-bottom:1px solid var(--rule);display:flex;justify-content:space-between;align-items:baseline;font-family:var(--mono);font-weight:500;line-height:1.5}.section-head:before{content:'#';margin-right:10px;color:var(--forge);font-family:var(--serif);font-size:14px;font-style:italic}.aside{color:var(--paper-mute);font-size:10px;letter-spacing:.24em}.verdict{display:grid;grid-template-columns:auto 1fr;gap:56px;padding:48px 0;border-bottom:1px solid var(--rule);align-items:center}.grade-stamp{width:220px;height:220px;border:3px solid var(--grade-b);color:var(--grade-b);display:flex;flex-direction:column;align-items:center;justify-content:center;transform:rotate(-4deg)}.grade-letter{font-family:var(--serif);font-style:italic;font-weight:900;font-size:112px;line-height:1}.grade-score{font-size:13px;letter-spacing:.1em}.verdict-body{display:flex;flex-direction:column;gap:18px}.verdict-headline{font-family:var(--serif);font-style:italic;font-weight:600;font-size:38px;line-height:1.15}.verdict-headline em{color:var(--forge)}.verdict-stats{display:grid;grid-template-columns:repeat(4,1fr);border-top:1px solid var(--rule);padding-top:20px}.stat{border-right:1px solid var(--rule);padding:0 18px}.stat:first-child{padding-left:0}.stat:last-child{border-right:0}.verdict-stats .num{font-family:var(--serif);font-weight:800;font-size:32px;line-height:1}.verdict-stats .num.warn{color:var(--grade-c)}.verdict-stats .num.fail{color:var(--grade-f)}.verdict-stats .num.note{color:var(--advisory)}.lbl{font-size:10px;text-transform:uppercase;letter-spacing:.2em;color:var(--paper-mute);margin-top:8px}.pillars,.offenders,.chart-section{padding:48px 0;border-bottom:1px solid var(--rule)}.pillar-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--rule);border:1px solid var(--rule)}.pillar{background:var(--ink-2);padding:24px 20px;display:flex;flex-direction:column;gap:14px}.pillar .name{font-size:10px;text-transform:uppercase;letter-spacing:.24em;color:var(--paper-mute)}.pillar .grade{font-family:var(--serif);font-weight:800;font-style:italic;font-size:52px;line-height:.9}.grade.a,.grade-pill.a{color:var(--grade-a)}.grade.b,.grade-pill.b{color:var(--grade-b)}.grade.c,.grade-pill.c{color:var(--grade-c)}.grade.d,.grade-pill.d{color:var(--grade-d)}.grade.f,.grade-pill.f{color:var(--grade-f)}.breakdown{font-size:11px;color:var(--paper-dim);line-height:1.7}.row{display:flex;justify-content:space-between;gap:8px}.key{color:var(--paper-mute)}table{width:100%;border-collapse:collapse;font-size:13px;table-layout:auto;font-family:var(--mono)}th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--paper-mute);font-weight:500;padding:12px 14px 12px 0;border-bottom:1px solid var(--rule)}th:last-child,td:last-child{padding-right:0}th.num,td.num{text-align:right;padding-left:18px}td{padding:14px 14px 14px 0;border-bottom:1px solid var(--ink-3);color:var(--paper-dim);font-size:13px;font-family:var(--mono);font-weight:500;line-height:1.4}td.num{color:var(--paper);font-variant-numeric:tabular-nums}.file-path{color:var(--paper);font-weight:500}.grade-pill{display:inline-block;font-family:var(--serif);font-style:italic;font-weight:800;font-size:18px;line-height:1;padding:4px 10px;border:1.5px solid currentColor;min-width:36px;text-align:center}.chart-summary{color:var(--paper-dim);font-size:12px;margin:-6px 0 18px}.chart-card{border:1px solid var(--rule);padding:24px;background:var(--ink-3)}.title{font-size:10px;text-transform:uppercase;letter-spacing:.2em;color:var(--paper-mute);margin-bottom:24px}.histogram{display:flex;align-items:flex-end;gap:6px;height:180px;padding-bottom:20px;border-bottom:1px solid var(--rule)}.bar{flex:1;background:var(--forge);position:relative;min-height:4px}.bar.warn{background:var(--grade-c)}.bar.fail{background:var(--grade-f)}.bar .count{position:absolute;top:-22px;left:50%;transform:translateX(-50%);font-size:11px}.histogram-axis{display:flex;gap:6px;margin-top:8px;font-size:10px;color:var(--paper-mute)}.histogram-axis span{flex:1;text-align:center}.findings{padding:48px 0}.finding{display:grid;grid-template-columns:auto 1fr auto;gap:24px;padding:18px 0;border-bottom:1px solid var(--ink-3);align-items:start}.severity{font-size:9px;text-transform:uppercase;letter-spacing:.24em;padding:4px 10px;border:1px solid currentColor;margin-top:2px;min-width:76px;text-align:center}.severity.fail{color:var(--grade-f)}.severity.warn{color:var(--grade-c)}.severity.note{color:var(--paper-mute)}.rule{font-size:10px;color:var(--forge);text-transform:uppercase;letter-spacing:.16em;margin-bottom:6px;font-family:var(--mono);font-weight:700;line-height:1.5}.msg{font-family:var(--serif);font-weight:500;font-size:17px;color:var(--paper);line-height:1.4}.loc{font-size:11px;color:var(--paper-mute);margin-top:8px}.loc code{color:var(--paper-dim);background:var(--ink-3);padding:1px 6px;border:1px solid var(--rule)}.loc-link{color:inherit;text-decoration:none}.loc-link[href]{text-decoration:underline;text-decoration-color:var(--rule);text-underline-offset:3px}.loc-link:focus-visible{outline:2px solid var(--forge);outline-offset:3px}.points{font-size:10px;color:var(--paper-mute);text-align:right;letter-spacing:.1em;min-width:96px;padding-left:12px}.empty{color:var(--paper-dim);font-size:12px}.footer{margin-top:48px;padding-top:24px;border-top:1px solid var(--rule);display:grid;grid-template-columns:1fr auto 1fr;gap:24px;align-items:center;font-size:10px;color:var(--paper-mute);letter-spacing:.12em;text-transform:uppercase}.center{font-family:var(--serif);font-style:italic;font-size:13px;color:var(--paper-dim);text-transform:none;letter-spacing:0}.right{text-align:right}@media(max-width:900px){body{padding:16px}.paper{padding:28px 20px}.wordmark{font-size:64px}.masthead,.verdict{grid-template-columns:1fr}.meta{text-align:left}.grade-stamp{margin:0 auto}.pillar-grid{grid-template-columns:repeat(2,1fr)}.verdict-stats{grid-template-columns:repeat(2,1fr);gap:16px}.stat{border-right:0;padding:0}.verdict-headline{font-size:28px}}@media(max-width:560px){.pillar-grid{grid-template-columns:1fr}.finding{grid-template-columns:1fr}.points{text-align:left;padding-left:0}.footer{grid-template-columns:1fr}.right{text-align:left}}
"""

_DIAGNOSTICS_CSS = r"""
.diagnostics{padding:28px 0 0}.diagnostic-list{display:grid;gap:10px}.diagnostic{display:grid;grid-template-columns:auto 1fr;gap:10px 14px;border:1px solid var(--rule);background:var(--ink-3);padding:12px 14px;color:var(--paper-dim);font-size:12px}.diagnostic-type{text-transform:uppercase;letter-spacing:.14em;color:var(--forge);font-size:10px}.diagnostic-location{grid-column:2;color:var(--paper-mute);font-size:11px}
"""

_FILTER_CSS = r"""
.finding-filters{border:1px solid var(--rule);background:var(--ink-3);padding:18px;margin:0 0 22px;display:grid;gap:16px}.filter-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.finding-filters label,.filter-group legend{display:flex;flex-direction:column;gap:7px;color:var(--paper-mute);font-size:10px;text-transform:uppercase;letter-spacing:.14em}.finding-filters input,.finding-filters select{width:100%;border:1px solid var(--rule);background:var(--ink);color:var(--paper);padding:8px 10px;font:12px var(--mono)}.finding-filters select{min-height:96px}.finding-filters input:focus-visible,.finding-filters select:focus-visible,.finding-filters button:focus-visible{outline:2px solid var(--forge);outline-offset:3px}.filter-group{border:0;display:flex;align-items:center;gap:14px;flex-wrap:wrap}.filter-group legend{margin-right:4px}.filter-group .radio{flex-direction:row;align-items:center;text-transform:none;letter-spacing:0;font-size:12px;color:var(--paper-dim)}.filter-group input{width:auto}.filter-actions{display:flex;justify-content:space-between;align-items:center;gap:16px}.filter-actions button{border:1px solid var(--forge);background:var(--forge);color:var(--ink);padding:9px 12px;font:700 12px var(--mono);cursor:pointer}.filter-count{color:var(--paper-dim);font-size:12px}.finding-group{border-top:1px solid var(--rule);padding-top:10px}.finding-group-title{font:700 11px var(--mono);letter-spacing:.14em;text-transform:uppercase;color:var(--paper-dim);margin:12px 0 2px}@media(max-width:900px){.filter-grid{grid-template-columns:1fr 1fr}.filter-actions{align-items:flex-start;flex-direction:column}}@media(max-width:560px){.filter-grid{grid-template-columns:1fr}}
"""
