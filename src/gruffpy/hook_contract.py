"""Agent-hook contract projection for ``gruff.hook.v2``.

The hook contract is intentionally separate from the canonical analysis
envelope. Hook mode runs the normal analyser, then projects findings into the
cross-analyser shape an agent PostToolUse hook can render without per-language
logic.
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
    """Findings retained for hook output plus changed-region suppression count."""

    findings: tuple[Finding, ...]
    suppressed_count: int


def capabilities_payload() -> dict[str, Any]:
    """Return the advertised hook contract capability payload.

    Returns:
        JSON-serializable capabilities for `gruff-py hook --capabilities`,
        including the contract version, supported hook features, flag names,
        and flag-order declaration.
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
        JSON-serializable hook payload with no findings, `schemaOk: false`, and
        the analyzer's config error as an object carrying its remediation.
    """
    payload = fatal_payload("config", str(exc))
    payload["config"] = {
        "schemaOk": False,
        "error": {"message": str(exc), "remediation": _CONFIG_ERROR_REMEDIATION},
    }
    return payload


def fatal_payload(diagnostic_type: str, message: str) -> dict[str, Any]:
    """Return the empty payload that accompanies a run which could not happen.

    Every field the contract requires is present and empty, so a consumer parses
    one shape whether the run succeeded or not and reads the reason from the
    fatal diagnostic rather than scraping stderr.

    Args:
        diagnostic_type: Stable machine-readable kind, such as `config`,
            `baseline`, or `changed-region`.
        message: One sentence saying what stopped the run.

    Returns:
        JSON-serializable hook payload carrying one fatal diagnostic.
    """
    return {
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": {"name": TOOL_NAME, "version": VERSION},
        "run": _run_payload(mode="full", scope="file", paths=(), analysed_files=0, baseline_path=None),
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
) -> dict[str, Any]:
    """Build the audit block a consumer reads before trusting a verdict.

    Without it a clean payload is ambiguous, because a run that analysed nothing
    and a run that found nothing look identical on the wire.

    Args:
        mode: Which region selector chose the work: changed-ranges, diff, since, or full.
        scope: How wide each changed line was taken to be: symbol, hunk, or file.
        paths: The operands as the caller gave them.
        analysed_files: How many files were actually analysed; zero is reported, never hidden.
        baseline_path: Project-relative baseline that classified the run, or None.

    Returns:
        The `run` block of the hook payload.
    """
    return {
        "mode": mode,
        "scope": scope,
        "paths": list(paths),
        "analysedFiles": analysed_files,
        "baseline": {
            "applied": baseline_path is not None,
            "schemaVersion": BASELINE_SCHEMA_VERSION if baseline_path is not None else None,
            "path": baseline_path,
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
    """Project an analysis report into the `gruff.hook.v2` payload.

    Args:
        report: Native analysis report produced by the normal analyser runner
            before the v3 machine adapter projects it.
        paths: Requested hook path arguments, used to map explicit
            `--changed-ranges` onto files.
        changed_ranges: Raw explicit changed-range string from the hook CLI.
        base_stable_identities: Hook stable identities from the git base tree,
            each with its occurrence count, when a new-only comparison is active.
        mode: Which region selector chose the work, for the run audit block.
        baseline_path: Project-relative baseline that classified the run, or None.
        baseline_statuses: Baseline status per finding, keyed by `id(finding)`;
            empty when no baseline was applied.
        suppressions: One section 13a audit row per configured sensitive
            exclusion, zero matches included.

    Returns:
        JSON-serializable hook contract payload with filtered findings, the run
        audit block, the exclusion audit, ignored paths, and config status.
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
        ),
        "findings": [_finding_payload(finding, identities[index], statuses.get(id(finding))) for index, finding in enumerate(findings)],
        "suppressed": {"count": filtered.suppressed_count},
        "suppressions": [_suppression_payload(summary) for summary in suppressions],
        "ignored": {"paths": [detail.to_dict() for detail in report.ignored_path_details]},
        "diagnostics": [_diagnostic_payload(diagnostic) for diagnostic in report.diagnostics],
        "config": {"schemaOk": True, "error": None},
    }


def _suppression_payload(summary: SuppressionSummary) -> dict[str, Any]:
    """Project one sensitive exclusion, configured or built in, into its section 13a audit row.

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
        # Only a built-in row names its source; a configured row is recognised by carrying none.
        **({} if summary.source is None else {"source": summary.source}),
    }


def _diagnostic_payload(diagnostic: RunDiagnostic) -> dict[str, Any]:
    """Project one run diagnostic into the v2 shape, where every entry says what it means for the run.

    v1 left a consumer to infer severity from the diagnostic type, so a budget
    note and a run that could not happen looked alike.

    Args:
        diagnostic: One diagnostic the run produced.

    Returns:
        The JSON row, carrying an explicit severity beside the v1 fields.
    """
    payload: dict[str, Any] = dict(diagnostic.to_dict())
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
        paths: Requested paths to which explicit changed ranges apply.
        changed_ranges: Explicit range text; None disables region filtering, while an empty string is invalid.
        base_stable_identities: Prior occurrence counts; None disables identity-based new-only filtering.
        has_prior_base: Whether a Git comparison or applied baseline can attribute file and project findings to the edit.

    Returns:
        Retained findings in input order and the count removed by changed-region rules, excluding new-only removals alone.

    Raises:
        ValueError: If explicit changed-range syntax is invalid.
    """
    changed = _changed_region_set(findings, paths, changed_ranges)
    kept: list[Finding] = []
    suppressed_count = 0
    scopes = [_scope_for_finding(finding) for finding in findings]
    covered = _base_covered_findings(findings, scopes, base_stable_identities)

    for index, finding in enumerate(findings):
        scope = scopes[index]

        if changed.active:
            if scope in {"file", "project"}:
                # Without a prior base the hook cannot attribute a whole-file issue to this edit, and a base that
                # already held this occurrence says the edit did not introduce it.
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
) -> set[int]:
    """Pick the current findings the base already held, spending each key's base count on its lowest lines first.

    One base occurrence covers one current occurrence, never every occurrence of its key, so a duplicate an edit added
    stays visible. Counts are spent lowest line first, as baseline matching spends a reviewed count, before any region
    filter applies.

    Args:
        findings: Every current finding, before any region filtering.
        scopes: Each finding's hook scope, aligned by index.
        base_counts: Occurrences of each hook stable identity in the base; None when no base was compared.

    Returns:
        Indexes of the findings the base covers; empty without a base.
    """
    if base_counts is None:
        return set()
    remaining = Counter(base_counts)
    covered: set[int] = set()
    # Spend lowest line first, so the occurrences a base already had are the ones it covers when an edit appends one.
    for index in sorted(range(len(findings)), key=lambda position: (findings[position].line or 0, findings[position].column or 0, position)):
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
        finding: Finding supplying the rule, file, and either its symbol or fallback message.
        scope: Explicit scope, or None or empty text to infer it from the finding.

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
) -> Counter[str]:
    """Analyze the git base tree and count its hook stable identities.

    Args:
        project_root: Git working tree where the hook command was invoked.
        paths: Requested hook paths to materialize from the base tree.
        diff_ref: Git ref supplied to `--diff`; `working-tree` maps to `HEAD`.
        config_path: Explicit config file from the hook CLI, when supplied.
        no_config: Whether config discovery is disabled.
        include_ignored: Whether default-ignored and gitignored paths are
            included in the base analysis.
        deep_scan_budget: Raw ``--deep-scan-budget`` text forwarded to the base
            analysis, so the base and working trees are bounded identically; empty
            when the hook passed no override.

    Returns:
        How many times each hook stable identity occurs in the requested base tree.
    """
    base_ref = "HEAD" if diff_ref == "working-tree" else diff_ref
    with tempfile.TemporaryDirectory(prefix="gruff-hook-base-") as tmp:
        base_root = Path(tmp)
        _materialize_git_base(project_root, base_root, base_ref, paths)
        base_config_path = config_path
        if not no_config and base_config_path is None:
            base_config_path = existing_config_source(project_root)
        report = run_analysis(
            AnalysisRunRequest(
                paths=paths or (".",),
                config_path=base_config_path,
                no_config=no_config,
                output=OutputFormat.JSON,
                fail_threshold=FailThreshold.NONE,
                include_ignored=include_ignored,
                project_root=base_root,
                display_filter=FindingDisplayFilter(),
                baseline=BaselineOptions(disabled=True),
                deep_scan_budget=deep_scan_budget,
            )
        )
        return Counter(_hook_stable_identity(finding, _scope_for_finding(finding)) for finding in report.findings)


def render_json(payload: dict[str, Any]) -> str:
    """Render a hook payload with the same indentation as JSON reports.

    Args:
        payload: JSON-serializable hook payload.

    Returns:
        Pretty-printed JSON terminated with a newline.
    """
    return json.dumps(payload, indent=4) + "\n"


def _finding_payload(finding: Finding, identity: Any = None, baseline_status: str | None = None) -> dict[str, Any]:
    """Project one finding into the v2 shape, carrying the four fields v1 never published.

    Args:
        finding: The finding to reshape.
        identity: This finding's ratified family identity, or None where the
            family refuses to name it, which is every sensitive finding.
        baseline_status: What an applied baseline made of it; None when none was.

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

    A consumer locating a finding cannot treat an absent end as a single line by
    guessing, so the contract makes the field required and the single-line case
    explicit.

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

    A finding naming no symbol reports 0, which is what the identity contract
    says a symbol-less subject carries.

    Args:
        identity: Ratified identity carrying a subject, or None when the finding has no identity.

    Returns:
        The ASCII-digit suffix after the subject's last #, or 0 when no valid suffix is available.
    """
    if identity is None:
        return 0
    subject = identity.subject
    marker = subject.rfind("#")
    if marker < 0:
        return 0
    tail = subject[marker + 1 :]
    # `str.isdigit` accepts non-ASCII digits, which `int` would then read as a number this module never wrote.
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
        A shallow copy; when threshold is present, missing comparison aliases are filled where available and existing values remain intact.
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
        metadata: Comparison metadata inspected in the function's metric-priority order.

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


def _changed_region_set(
    findings: tuple[Finding, ...],
    paths: tuple[str, ...],
    changed_ranges: str | None,
) -> ChangedRegionSet:
    # Only an absent flag means no filter. An empty value asks to scope the run and names no range, so it
    # goes to the parser, which refuses it, rather than silently widening the scan to the whole tree.
    """Resolve explicit hook ranges against requested paths and paths named by findings.

    Args:
        findings: Findings whose file paths join the set receiving explicit ranges.
        paths: Requested path spellings, normalised to forward slashes with outer slashes removed.
        changed_ranges: Range text to parse; None disables the filter, while empty text is rejected.

    Returns:
        An inactive set when no range flag was supplied, otherwise an explicit set for the nonempty normalised paths.

    Raises:
        ValueError: If explicit changed-range syntax is invalid.
    """
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
) -> None:
    """Write selected files from a Git tree into the base-analysis directory.

    Args:
        project_root: Repository from which Git resolves the base ref and reads file blobs.
        target_root: Directory receiving the selected relative paths and their blob bytes.
        base_ref: Git tree or commit ref whose files are materialised.
        paths: Git pathspecs selecting files; empty selects the whole tree.

    Raises:
        ValueError: If a Git command cannot resolve or read the requested tree.
        OSError: If a destination directory or file cannot be written.
    """
    pathspecs = list(paths or (".",))
    tree_paths = _git_lines(
        project_root,
        ["ls-tree", "-r", "--name-only", base_ref, "--", *pathspecs],
    )
    for rel_path in tree_paths:
        if rel_path.startswith("/") or ".." in Path(rel_path).parts:
            continue
        blob = _git_bytes(project_root, ["show", f"{base_ref}:{rel_path}"])
        target = target_root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)


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
