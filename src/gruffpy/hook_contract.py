"""Translate analysis results into `gruff.hook.v2` for coding-agent hooks.

The hook uses the normal analyser so agent results come from the same rule engine as a terminal scan.
This module applies the requested attribution and packages findings, diagnostics and suppressions for the agent.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import BaselineOptions
from gruffpy.analysis.changed_region import ChangedRegionSet, parse_explicit_ranges
from gruffpy.analysis.machine_contract import diagnostic_file_path, project_relative_path
from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.run_diagnostic import RunDiagnostic
from gruffpy.analysis.runner import run_analysis
from gruffpy.analysis.suppression_summary import SuppressionSummary
from gruffpy.command.init_config import existing_config_source
from gruffpy.config.exceptions import ConfigError
from gruffpy.finding.baseline_identity import finding_identities
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.severity import Severity
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.rule.catalog import documentation_for_rule
from gruffpy.version import TOOL_NAME, VERSION

HOOK_CONTRACT_VERSION = "gruff.hook.v2"

BASELINE_SCHEMA_VERSION = "gruff.baseline.v3"

_ASCII_DIGITS = re.compile(r"[0-9]+")

_CONFIG_ERROR_REMEDIATION = "Fix the reported problem in the project configuration, or pass --no-config to run without it."

_SEVERITY_SORT_RANK = {
    Severity.ERROR: 0,
    Severity.WARNING: 1,
    Severity.ADVISORY: 2,
}

_FILE_SCOPE_RULE_IDS = frozenset(
    {
        "docs.missing-module-docstring",
        "docs.todo-density",
        "naming.test-naming-consistency",
        "size.file-length",
        "test-quality.naming-consistency",
    }
)

_LINE_UNITS_BY_METADATA_KEY = (
    "lines",
    "averageLines",
)

_COUNT_UNITS_BY_METADATA_KEY = (
    "assertions",
    "attributes",
    "cycles",
    "fieldCount",
    "groupSize",
    "markers",
    "methodCount",
    "mocks",
    "parameters",
    "publicMethods",
)

_MEASURED_METADATA_KEYS = (*_LINE_UNITS_BY_METADATA_KEY, *_COUNT_UNITS_BY_METADATA_KEY)


@dataclass(frozen=True, slots=True)
class _HookFilterResult:
    """Carry the findings and suppression count for a hook response.

    The agent sees the retained findings as review prompts.
    The count explains how many findings were removed by the changed-region filter.
    """

    findings: tuple[Finding, ...]
    suppressed_count: int


def capabilities_payload() -> dict[str, Any]:
    """Return the advertised hook contract capability payload.

    Returns:
        JSON-serializable capabilities for gruff-py hook --capabilities, including the contract version and supported hook features,
        flag names and the flag-order declaration.
    """
    return {
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": {"name": TOOL_NAME, "version": VERSION},
        "supports": {
            "baseline": True,
            "baselineV3": True,
            "changedRanges": True,
            "confidenceGate": True,
            "deepScanBudget": True,
            "diagnostics": True,
            "diff": True,
            "ignoreReport": True,
            "metadata": True,
            "newOnly": True,
            "scopeField": True,
            "stableIdentity": True,
        },
        "flags": {
            "baseline": "--baseline",
            "changedRanges": "--changed-ranges",
            "deepScanBudget": "--deep-scan-budget",
            "diff": "--diff",
            "failOnDiagnostics": "--fail-on-diagnostics",
            "minConfidence": "--min-confidence",
        },
        "flagOrder": "any",
    }


def config_error_payload(exc: ConfigError) -> dict[str, Any]:
    """Return a hook payload for configuration failures.

    Args:
        exc: Config loading or schema validation failure raised before analysis
            can run.

    Returns:
        JSON-serializable hook payload with no findings, schemaOk set to false, and a configuration error object with remediation.
    """
    payload = fatal_payload("config", str(exc))
    payload["config"] = {
        "schemaOk": False,
        "error": {"message": str(exc), "remediation": _CONFIG_ERROR_REMEDIATION},
    }
    return payload


def fatal_payload(diagnostic_type: str, message: str) -> dict[str, Any]:
    """Build a fatal hook payload when a failure prevents a successful hook result.

    Required fields retain their normal shape, with no findings or analysed files.
    The fatal diagnostic carries the reason so consumers do not need to scrape stderr.

    Args:
        diagnostic_type: Stable machine-readable kind, such as `config`,
            `baseline`, or `changed-region`.
        message: Error detail published as the fatal diagnostic message.

    Returns:
        JSON-serializable hook payload carrying one fatal diagnostic.
    """
    return {
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": {"name": TOOL_NAME, "version": VERSION},
        "run": _run_payload(mode="full", scope="file", paths=(), analysed_files=0, baseline_path=None, project_root="."),
        "findings": [],
        "suppressed": {"count": 0},
        "suppressions": [],
        "ignored": {"paths": []},
        "diagnostics": [
            {
                "type": diagnostic_type,
                "severity": "fatal",
                "message": message,
                "file": None,
                "line": None,
                "path": None,
            }
        ],
        "config": {"schemaOk": True, "error": None},
    }


def _run_payload(
    *,
    mode: str,
    scope: str,
    paths: tuple[str, ...],
    analysed_files: int,
    baseline_path: str | None,
    project_root: str,
) -> dict[str, Any]:
    """Describe the scope and comparison used to reach a hook verdict.
    The agent can distinguish a scan with zero analysed files from a completed scan that returned no findings.

    Args:
        mode: Which region selector chose the work: changed-ranges, diff, since, or full.
        scope: How wide each changed line was taken to be: symbol, hunk, or file.
        paths: The operands as the caller gave them.
        analysed_files: How many files were actually analysed; zero is reported, never hidden.
        baseline_path: Baseline that classified the run, or None when no baseline was applied.
        project_root: Root used to publish an applied baseline's location when it lies within the project.

    Returns:
        The `run` block. A missing baseline leaves its schema and path null. An applied external baseline is recorded without its host path.
    """
    return {
        "mode": mode,
        "scope": scope,
        "paths": list(paths),
        "analysedFiles": analysed_files,
        "baseline": {
            "applied": baseline_path is not None,
            "schemaVersion": BASELINE_SCHEMA_VERSION if baseline_path is not None else None,
            "path": project_relative_path(baseline_path, project_root) if baseline_path is not None else None,
        },
    }


def hook_payload(
    report: AnalysisReport,
    *,
    paths: tuple[str, ...],
    changed_ranges: str | None = None,
    base_stable_identities: Counter[str] | None = None,
    mode: str = "full",
    baseline_path: str | None = None,
    baseline_statuses: dict[int, str] | None = None,
    suppressions: tuple[SuppressionSummary, ...] = (),
) -> dict[str, Any]:
    """Translate a completed analysis into the agent's `gruff.hook.v2` response.
    The hook applies changed-region attribution and reports what it kept, what it suppressed and whether the scan was usable.

    Args:
        report: Native analysis report produced by the normal analyser runner
            before the v3 machine adapter projects it.
        paths: Requested hook path arguments, used to map explicit --changed-ranges onto files.
        changed_ranges: Range text; None disables region filtering, while empty or invalid text raises ValueError.
        base_stable_identities: Git base occurrence counts. None disables identity filtering.
            An empty counter still establishes a prior base for attributing file and project findings to the edit.
        mode: Which region selector chose the work, for the run audit block.
        baseline_path: Path to the applied baseline as supplied by the caller. None means no baseline was applied.
        baseline_statuses: Status keyed by id(finding). None or a missing entry publishes a null baselineStatus.
        suppressions: Configured, built-in, inline and duplicate audit rows for the hook; include zero-match configured exclusions.

    Returns:
        JSON-serializable hook payload with findings, diagnostics, run details, suppression audit rows, ignored paths and config status.
        The suppressed count covers changed-region removals. Findings removed only by the new-only filter do not contribute.

    Raises:
        ValueError: If explicit changed-range syntax is invalid.
    """
    filtered = _filter_findings_for_hook(
        report.findings,
        paths=paths,
        changed_ranges=changed_ranges,
        base_stable_identities=base_stable_identities,
        # An applied baseline is a prior base too: it is what lets a whole-file finding be attributed to this edit.
        has_prior_base=base_stable_identities is not None or baseline_path is not None,
    )
    findings = sorted(
        filtered.findings,
        key=lambda finding: (
            _SEVERITY_SORT_RANK[finding.severity],
            finding.file_path,
            finding.line if finding.line is not None else 0,
            finding.rule_id,
        ),
    )
    identities = finding_identities(findings)
    statuses = baseline_statuses or {}
    return {
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": {"name": TOOL_NAME, "version": report.tool_version},
        "run": _run_payload(
            mode=mode,
            scope="file" if mode == "full" else "symbol",
            paths=paths,
            analysed_files=report.files_parsed,
            baseline_path=baseline_path,
            project_root=report.machine_context.project_root,
        ),
        "findings": [_finding_payload(finding, identities[index], statuses.get(id(finding))) for index, finding in enumerate(findings)],
        "suppressed": {"count": filtered.suppressed_count},
        "suppressions": [_suppression_payload(summary) for summary in suppressions],
        "ignored": {"paths": [detail.to_dict() for detail in report.ignored_path_details]},
        "diagnostics": [_diagnostic_payload(diagnostic, report.machine_context.project_root) for diagnostic in report.diagnostics],
        "config": {"schemaOk": True, "error": None},
    }


def _suppression_payload(summary: SuppressionSummary) -> dict[str, Any]:
    """Serialize a suppression audit row for the hook payload.

    Args:
        summary: Suppression audit entry, including its count, optional symbol and optional source.

    Returns:
        Hook audit fields using the first path or an empty path, omitting source only when it is None.
    """
    return {
        "rule": summary.rule,
        # Section 13a gives each entry exactly one path; the native audit carries it in the family's list shape.
        "path": summary.paths[0] if summary.paths else "",
        "symbol": summary.symbol,
        "reason": summary.reason,
        "suppressed": summary.suppressed,
        # Configured exclusions omit source; built-in, inline and duplicate suppressions retain their source label.
        **({} if summary.source is None else {"source": summary.source}),
    }


def _diagnostic_payload(diagnostic: RunDiagnostic, project_root: str) -> dict[str, Any]:
    """Publish a run diagnostic with the location and severity the agent needs to interpret it.
    A budget note is a warning and a run-invalidating diagnostic is fatal.

    Args:
        diagnostic: One diagnostic the run produced.
        project_root: Root used to project diagnostic paths.

    Returns:
        The diagnostic with project-relative locations and warning severity when invalidates_run is False, or fatal severity otherwise.
    """
    payload: dict[str, Any] = dict(diagnostic.to_dict())
    payload["file"] = diagnostic_file_path(diagnostic, project_root)
    # Pre-scan failures may have no operand path. Keep a link only when an input was recorded inside the project.
    if diagnostic.path is not None:
        payload["path"] = project_relative_path(diagnostic.path, project_root)
    payload["severity"] = "warning" if diagnostic.invalidates_run is False else "fatal"
    return payload


def _filter_findings_for_hook(
    findings: tuple[Finding, ...],
    *,
    paths: tuple[str, ...],
    changed_ranges: str | None = None,
    base_stable_identities: Counter[str] | None = None,
    has_prior_base: bool = False,
) -> _HookFilterResult:
    """Apply hook changed-region and new-only semantics to full-scan findings.

    Args:
        findings: Full-scan findings in the order retained by this filter.
        paths: Requested paths added to the finding paths when resolving explicit ranges. An empty tuple uses the finding paths alone.
        changed_ranges: Explicit range text; None disables region filtering, while an empty string is invalid.
        base_stable_identities: Prior occurrence counts; None disables identity-based new-only filtering.
        has_prior_base: Whether a Git comparison or applied baseline can attribute file and project findings to the edit.

    Returns:
        Retained findings in input order and the count removed by changed-region rules, excluding new-only removals alone.

    Raises:
        ValueError: If explicit changed-range syntax is invalid.
    """
    changed = changed_region_for_hook(findings, paths, changed_ranges)
    kept: list[Finding] = []
    suppressed_count = 0
    scopes = [_scope_for_finding(finding) for finding in findings]
    covered = _base_covered_findings(findings, scopes, base_stable_identities, changed)

    for index, finding in enumerate(findings):
        scope = scopes[index]

        if changed.active:
            if scope in {"file", "project"}:
                # Line ranges alone cannot attribute file or project findings to this edit, so both need a prior base.
                # A Git base occurrence assigned to this finding also rules it out as new.
                if not has_prior_base or index in covered:
                    suppressed_count += 1
                    continue
            elif not _is_finding_intersecting_changed_region(finding, changed):
                suppressed_count += 1
                continue

        if index in covered:
            continue

        kept.append(finding)

    return _HookFilterResult(findings=tuple(kept), suppressed_count=suppressed_count)


def _base_covered_findings(
    findings: tuple[Finding, ...],
    scopes: list[str],
    base_counts: Counter[str] | None,
    changed: ChangedRegionSet | None = None,
) -> set[int]:
    """Pick the current findings the base already held, spending each key's base count on unchanged locations first.

    One base occurrence covers one current occurrence; added duplicates beyond that count remain eligible before region filtering.

    Args:
        findings: Every current finding, before any region filtering.
        scopes: Each finding's hook scope, aligned by index.
        base_counts: Occurrences of each hook stable identity in the base; None when no base was compared.
        changed: Optional active changed-region set so untouched occurrences spend base credit before edited occurrences.

    Returns:
        Indexes of the findings the base covers; empty without a base.
    """
    if base_counts is None:
        return set()
    remaining = Counter(base_counts)
    covered: set[int] = set()
    changed_active = changed is not None and changed.active

    def spend_key(position: int) -> tuple[int, int, int, int]:
        """Rank occurrences outside changed lines ahead of changed occurrences, then lowest line first.

        Args:
            position: Index into findings for the candidate occurrence.

        Returns:
            Sort key ``(changed_rank, line, column, position)``.
        """
        finding = findings[position]
        in_changed = 1 if (changed_active and changed is not None and _is_finding_intersecting_changed_region(finding, changed)) else 0
        return (in_changed, finding.line or 0, finding.column or 0, position)

    # Spend unchanged locations first (when changed ranges are active), then lowest line first.
    for index in sorted(range(len(findings)), key=spend_key):
        identity = _hook_stable_identity(findings[index], scopes[index])
        if remaining[identity] > 0:
            remaining[identity] -= 1
            covered.add(index)
    return covered


def _scope_for_finding(finding: Finding) -> str:
    """Classify a finding into the hook contract's closed scope enum.

    Args:
        finding: Finding whose start line, rule ID and optional symbol determine its scope.

    Returns:
        Project scope without a start line; otherwise file scope for designated rules, symbol scope for a non-None symbol, or line scope.
    """
    if finding.line is None:
        return "project"
    if finding.rule_id in _FILE_SCOPE_RULE_IDS:
        return "file"
    if finding.symbol is not None:
        return "symbol"
    return "line"


def _hook_stable_identity(finding: Finding, scope: str | None = None) -> str:
    """Build the hook comparison key without source-line positions.

    Args:
        finding: Finding supplying the rule and file. A non-None symbol takes precedence over the scope and message.
        scope: Scope used for a finding without a symbol. None or empty text infers that scope from the finding.

    Returns:
        A 16-character hash of the rule and file plus the symbol, file/project scope, or line-scoped message.
    """
    resolved_scope = scope or _scope_for_finding(finding)
    if finding.symbol is not None:
        payload: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "file": finding.file_path,
            "symbol": finding.symbol,
        }
    elif resolved_scope in {"file", "project"}:
        payload = {
            "ruleId": finding.rule_id,
            "file": finding.file_path,
            "scope": resolved_scope,
        }
    else:
        payload = {
            "ruleId": finding.rule_id,
            "file": finding.file_path,
            "message": finding.message,
        }
    return _stable_hash(payload)


def stable_identities_from_git_base(
    *,
    project_root: Path,
    paths: tuple[str, ...],
    diff_ref: str,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
    deep_scan_budget: str = "",
    execution_exclude_rules: tuple[str, ...] = (),
) -> Counter[str]:
    """Scan the selected Git tree to establish which findings were already present before the edit.
    Use the same rules and budget as the working-tree scan so old findings can be distinguished from new ones.

    Args:
        project_root: Git working tree where the hook command was invoked.
        paths: Git pathspecs to materialize and analyze; empty selects the whole base tree.
        diff_ref: Git ref supplied to `--diff`; `working-tree` maps to `HEAD`.
        config_path: Explicit config file. None looks for working-tree config first and leaves discovery to the base scan if none is found.
            The no_config flag disables config loading.
        no_config: Whether config discovery is disabled.
        include_ignored: Whether default-ignored and gitignored paths are
            included in the base analysis.
        deep_scan_budget: Override text shared with working-tree analysis; empty applies no override to the base scan.
        execution_exclude_rules: The same invocation rule exclusions used for the working tree.

    Returns:
        Counts by hook stable identity. An empty counter means the base was analyzed and produced no findings.

    Raises:
        ValueError: When a requested path sits outside the project root, base-tree materialisation fails,
            or the base analysis exits with a fatal diagnostic.
    """
    base_ref = "HEAD" if diff_ref == "working-tree" else diff_ref
    relative_paths = _project_relative_git_paths(project_root, paths)
    with tempfile.TemporaryDirectory(prefix="gruff-hook-base-") as tmp:
        base_root = Path(tmp)
        materialized_paths = _materialize_git_base(project_root, base_root, base_ref, relative_paths)
        # Newly added files do not exist in the base tree, so there are no prior findings to subtract.
        if not materialized_paths:
            return Counter()
        base_paths = tuple(path for path in relative_paths if (base_root / path).exists())
        # None of the edited paths exist in the base revision, such as files added since, so there are no earlier findings.
        if not base_paths:
            return Counter()
        base_config_path = config_path
        # Prefer the working-tree config when no explicit file was supplied so the comparison uses the same rules.
        if not no_config and base_config_path is None:
            base_config_path = existing_config_source(project_root)
        report = run_analysis(
            AnalysisRunRequest(
                paths=base_paths,
                config_path=base_config_path,
                no_config=no_config,
                output=OutputFormat.JSON,
                fail_threshold=FailThreshold.NONE,
                include_ignored=include_ignored,
                project_root=base_root,
                display_filter=FindingDisplayFilter(),
                baseline=BaselineOptions(disabled=True),
                deep_scan_budget=deep_scan_budget,
                execution_exclude_rules=execution_exclude_rules,
            )
        )
        fatal = next((diagnostic for diagnostic in report.diagnostics if diagnostic.invalidates_run is not False), None)
        # A failed base scan must not masquerade as clean history and flag every unchanged finding as new.
        if fatal is not None or report.exit_code == 2:
            detail = fatal.message if fatal is not None else "base analysis failed"
            raise ValueError(f"Base revision {base_ref!r} analysis failed: {detail}")
        # Use findings before the display floor so visibility settings do not make an unchanged issue look new.
        findings = report.machine_context.summary_findings
        return Counter(_hook_stable_identity(finding, _scope_for_finding(finding)) for finding in (report.findings if findings is None else findings))


def _project_relative_git_paths(project_root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
    """Rewrite hook path operands as project-relative POSIX pathspecs for base-tree materialisation and analysis.

    Args:
        project_root: Live repository root the operands are validated against.
        paths: Caller-supplied path operands; empty selects the whole root (``"."``).

    Returns:
        Deduplicated project-relative POSIX pathspecs usable both by ``git ls-tree`` and by analysis under the temporary base checkout.

    Raises:
        ValueError: When an operand resolves outside ``project_root``.
    """
    # A hook run without path operands checks the whole project.
    if not paths:
        return (".",)
    resolved_root = project_root.resolve()
    relative_paths: list[str] = []
    # Rewrite each operand relative to the project, so the same pathspec works in the temporary base checkout.
    for raw_path in paths:
        # An empty operand or "." means the whole project.
        if raw_path in {"", "."}:
            relative_paths.append(".")
            continue
        candidate = Path(raw_path)
        resolved = candidate.resolve() if candidate.is_absolute() else (resolved_root / candidate).resolve()
        # An operand such as ../other/app.py cannot be replayed inside this repository's base revision.
        if not resolved.is_relative_to(resolved_root):
            raise ValueError(f"Input path resolves outside the project root: {raw_path}")
        relative = resolved.relative_to(resolved_root).as_posix()
        relative_paths.append("." if relative == "." else relative)
    return tuple(dict.fromkeys(relative_paths))


def render_json(payload: dict[str, Any]) -> str:
    """Render a hook payload with the same indentation as JSON reports.

    Args:
        payload: JSON-serializable hook payload.

    Returns:
        Pretty-printed JSON terminated with a newline.
    """
    return json.dumps(payload, indent=4) + "\n"


def _finding_payload(finding: Finding, identity: Any = None, baseline_status: str | None = None) -> dict[str, Any]:
    """Build a hook finding entry with location, scope, identities, remediation and metadata.

    Args:
        finding: The finding to reshape.
        identity: Baseline identity supplying stableIdentity and symbolOrdinal; None publishes a null identity and ordinal 0.
        baseline_status: Baseline classification to publish. None emits a null baselineStatus when no classification was supplied.

    Returns:
        JSON-serializable hook finding entry.
    """
    scope = _scope_for_finding(finding)
    return {
        "ruleId": finding.rule_id,
        "pillar": finding.pillar.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "scope": scope,
        "file": finding.file_path,
        "line": finding.line,
        "endLine": _end_line_for(finding),
        "symbol": finding.symbol,
        "symbolOrdinal": _symbol_ordinal_from(identity),
        "message": finding.message,
        "remediation": _remediation_for(finding),
        "baselineStatus": baseline_status,
        "metadata": _metadata_for(finding),
        "stableIdentity": identity.identity if identity is not None else None,
        "fingerprint": finding.fingerprint(),
    }


def _end_line_for(finding: Finding) -> int | None:
    """Return the span end every v2 finding carries, repeating the start line when the rule reported no span.

    The required endLine field makes single-line spans explicit rather than leaving consumers to infer them.

    Args:
        finding: Finding whose reported start and optional end define the published span.

    Returns:
        None without a start line; otherwise a valid reported end or the start line when the end is absent or earlier.
    """
    if finding.line is None:
        return None
    if finding.end_line is not None and finding.end_line >= finding.line:
        return finding.end_line
    return finding.line


def _symbol_ordinal_from(identity: Any) -> int:
    """Return the declaration ordinal the ratified identity hashed, so a consumer can recompute it.

    A symbol-less subject comes from the finding's message and has no declaration ordinal, so the hook reports 0.

    Args:
        identity: Ratified identity carrying a subject, or None when the finding has no identity.

    Returns:
        The integer after the subject's last # if written with ASCII digits, or 0 when no valid suffix is available.
    """
    if identity is None:
        return 0
    subject = identity.subject
    marker = subject.rfind("#")
    if marker < 0:
        return 0
    tail = subject[marker + 1 :]
    # Require ASCII decimal digits so ordinal parsing rejects Unicode forms, including digits int cannot convert.
    return int(tail) if _ASCII_DIGITS.fullmatch(tail) else 0


def _remediation_for(finding: Finding) -> str:
    """Choose remediation supplied by the finding or its rule documentation.

    Args:
        finding: Finding whose nonempty remediation takes precedence over catalogue guidance.

    Returns:
        The supplied remediation, the rule's fix guidance, or generic review guidance for an unknown rule.
    """
    if finding.remediation:
        return finding.remediation
    try:
        return documentation_for_rule(finding.rule_id).fix_guidance
    except KeyError:
        return "Review the finding and adjust the code or configuration deliberately."


def _metadata_for(finding: Finding) -> dict[str, Any]:
    """Copy finding metadata and fill missing threshold-comparison display fields.

    Args:
        finding: Finding whose metadata is copied without changing the original mapping.

    Returns:
        A shallow copy with existing fields preserved. A threshold key enables defaults for direction and unit.
        A missing measured field uses measuredValue when non-None, otherwise the first present metric alias.
        A None alias ends the lookup without adding measured, even if a later alias has a value.
    """
    metadata = dict(finding.metadata)
    if "threshold" not in metadata:
        return metadata
    measured = metadata.get("measuredValue")
    if measured is None:
        measured = _first_present(metadata, _MEASURED_METADATA_KEYS)
    if measured is not None:
        metadata.setdefault("measured", measured)
    metadata.setdefault("direction", metadata.get("thresholdDirection", "above"))
    metadata.setdefault("unit", _unit_for_metadata(finding.rule_id, metadata))
    return metadata


def _unit_for_metadata(rule_id: str, metadata: dict[str, Any]) -> str:
    """Choose the comparison unit from recognised metrics before using the rule fallback.

    Args:
        rule_id: Rule ID whose size prefix supplies a count fallback when no metric determines the unit.
        metadata: Metrics checked in priority order. A None value on the first present line or count alias skips that group.
            Density, volume and score metrics select a unit by key presence.

    Returns:
        The metric's unit label, count for an otherwise unclassified size rule, or value for another rule.
    """
    if _first_present(metadata, _LINE_UNITS_BY_METADATA_KEY) is not None:
        return "lines"
    if "densityPer1000" in metadata:
        return "per_1000_lines"
    if "halsteadVolume" in metadata:
        return "volume"
    if "complexity" in metadata or "cognitive" in metadata or "maintainabilityIndex" in metadata:
        return "score"
    if _first_present(metadata, _COUNT_UNITS_BY_METADATA_KEY) is not None:
        return "count"
    if rule_id.startswith("size."):
        return "count"
    return "value"


def _first_present(metadata: dict[str, Any], keys: tuple[str, ...]) -> Any | None:
    """Read the first requested metadata key that exists, without skipping a None value.

    Args:
        metadata: Mapping that may contain any of the requested keys.
        keys: Candidate keys in lookup-priority order; empty means no lookup succeeds.

    Returns:
        The first existing key's value, including None, or None when every key is absent.
    """
    for key in keys:
        if key in metadata:
            return metadata[key]
    return None


def changed_region_for_hook(
    findings: tuple[Finding, ...],
    paths: tuple[str, ...],
    changed_ranges: str | None,
) -> ChangedRegionSet:
    """Resolve explicit hook ``--changed-ranges`` against requested paths and paths named by findings.

    Shared by hook baseline credit spending and diff filtering so both agree on which lines count as edited.

    Args:
        findings: Findings whose project-relative file paths join the set receiving explicit ranges; empty relies on ``paths`` alone.
        paths: Requested path spellings, normalised to forward slashes with outer slashes removed; empty relies on ``findings`` alone.
        changed_ranges: Explicit range text such as ``"3-3,8-10"``; None disables filtering, while an empty string is rejected.

    Returns:
        An inactive set when ``changed_ranges`` is None, otherwise an explicit set covering the nonempty normalised paths.

    Raises:
        ValueError: If explicit changed-range syntax is invalid or empty.
    """
    # Only an absent --changed-ranges flag disables filtering; an empty string is passed to the parser to fail closed instead of widening the scan.
    if changed_ranges is None:
        return ChangedRegionSet(source="")
    source_paths = {
        *(path.replace("\\", "/").strip("/") for path in paths),
        *(finding.file_path for finding in findings),
    }
    return parse_explicit_ranges(tuple(sorted(path for path in source_paths if path)), changed_ranges)


def _is_finding_intersecting_changed_region(finding: Finding, changed: ChangedRegionSet) -> bool:
    """Test a finding against the selected changed file or line span.

    Args:
        finding: Finding whose file is tested directly when its start line is absent.
        changed: Resolved changed files and ranges to compare with the finding.

    Returns:
        Whether its file or reported span intersects the changed scope, using the start when its end is absent or earlier.
    """
    if finding.line is None:
        return changed.is_file_changed(finding.file_path)
    end_line = finding.end_line if finding.end_line is not None and finding.end_line >= finding.line else finding.line
    return changed.has_changed_range(finding.file_path, finding.line, end_line)


def _stable_hash(payload: dict[str, Any]) -> str:
    """Hash a hook identity payload with compact, ASCII-escaped JSON.

    Args:
        payload: Identity fields in their required insertion order, with JSON-serializable values.

    Returns:
        The first 16 lowercase SHA-256 hex characters after ASCII and forward-slash escaping.

    Raises:
        TypeError: If a payload value cannot be encoded as JSON.
        ValueError: If the payload contains a circular reference.
    """
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    encoded = encoded.replace("/", r"\/")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _materialize_git_base(
    project_root: Path,
    target_root: Path,
    base_ref: str,
    paths: tuple[str, ...],
) -> list[str]:
    """Write selected files from a Git tree into the base-analysis directory.

    Args:
        project_root: Repository from which Git resolves the base ref and reads file blobs.
        target_root: Directory receiving the selected relative paths and their blob bytes.
        base_ref: Git tree or commit ref whose files are materialised.
        paths: Git pathspecs selecting files; empty selects the whole tree.

    Returns:
        Project-relative paths actually written beneath target_root; empty when none existed in the base tree.

    Raises:
        ValueError: If a Git command cannot resolve or read the requested tree.
        OSError: If a destination directory or file cannot be written.
    """
    pathspecs = list(paths or (".",))
    tree_paths = _git_lines(
        project_root,
        ["ls-tree", "-r", "--name-only", base_ref, "--", *pathspecs],
    )
    materialized_paths: list[str] = []
    # Materialise each tracked base file into the temporary directory, rejecting any path that could escape target_root.
    for relative_path in tree_paths:
        if relative_path.startswith("/") or ".." in Path(relative_path).parts:
            continue
        blob = _git_bytes(project_root, ["show", f"{base_ref}:{relative_path}"])
        target = target_root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        materialized_paths.append(relative_path)
    return materialized_paths


def _git_lines(project_root: Path, args: list[str]) -> list[str]:
    """Read nonempty UTF-8 text lines from a Git command's standard output.

    Args:
        project_root: Repository selected through Git's -C option.
        args: Git subcommand and arguments to run in that repository.

    Returns:
        Output lines with empty lines omitted and undecodable bytes replaced.

    Raises:
        ValueError: If Git cannot start or the command exits unsuccessfully.
    """
    output = _git_bytes(project_root, args).decode("utf-8", errors="replace")
    return [line for line in output.splitlines() if line]


def _git_bytes(project_root: Path, args: list[str]) -> bytes:
    """Run a Git command and return its raw standard output.

    Args:
        project_root: Repository selected through Git's -C option.
        args: Git subcommand and arguments to execute.

    Returns:
        Standard-output bytes from the successful command.

    Raises:
        ValueError: If Git cannot start or the command exits unsuccessfully.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_root), *args],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"unable to resolve git base for hook diff: {exc}") from exc
    return completed.stdout
