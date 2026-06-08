"""Agent-hook contract projection for ``gruff.hook.v1``.

The hook contract is intentionally separate from ``gruff.analysis.v2`` so
existing analysis/report consumers keep their current payloads. Hook mode runs
the normal analyser, then projects findings into the cross-analyser shape an
agent PostToolUse hook can render without per-language logic.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gruffpy.analysis.analysis_run_request import AnalysisRunRequest
from gruffpy.analysis.baseline import BaselineOptions
from gruffpy.analysis.changed_region import ChangedRegionSet, parse_explicit_ranges
from gruffpy.analysis.report import AnalysisReport
from gruffpy.analysis.runner import run_analysis
from gruffpy.command.init_config import existing_config_source
from gruffpy.config.exceptions import ConfigError
from gruffpy.finding.fail_threshold import FailThreshold
from gruffpy.finding.finding import Finding
from gruffpy.finding.output_format import OutputFormat
from gruffpy.finding.severity import Severity
from gruffpy.reporting.finding_display_filter import FindingDisplayFilter
from gruffpy.rule.catalog import documentation_for_rule
from gruffpy.version import TOOL_NAME, VERSION

HOOK_CONTRACT_VERSION = "gruff.hook.v1"

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
            "changedRanges": True,
            "diff": True,
            "baseline": True,
            "scopeField": True,
            "metadata": True,
            "stableIdentity": True,
            "ignoreReport": True,
            "newOnly": True,
        },
        "flags": {
            "changedRanges": "--changed-ranges",
            "diff": "--diff",
            "baseline": "--baseline",
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
        the analyzer's config error message in-band.
    """
    return {
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": {"name": TOOL_NAME, "version": VERSION},
        "findings": [],
        "suppressed": {"count": 0},
        "ignored": {"paths": []},
        "config": {"schemaOk": False, "error": str(exc)},
    }


def hook_payload(
    report: AnalysisReport,
    *,
    paths: tuple[str, ...],
    changed_ranges: str = "",
    base_stable_identities: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Project an analysis report into the `gruff.hook.v1` payload.

    Args:
        report: Native `gruff.analysis.v2` report produced by the normal
            analyzer runner.
        paths: Requested hook path arguments, used to map explicit
            `--changed-ranges` onto files.
        changed_ranges: Raw explicit changed-range string from the hook CLI.
        base_stable_identities: Hook stable identities from a baseline or git
            base tree when a new-only comparison is active.

    Returns:
        JSON-serializable hook contract payload with filtered findings,
        suppressed count, ignored paths, and config status.
    """
    filtered = _filter_findings_for_hook(
        report.findings,
        paths=paths,
        changed_ranges=changed_ranges,
        base_stable_identities=base_stable_identities,
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
    return {
        "contractVersion": HOOK_CONTRACT_VERSION,
        "analyzer": {"name": TOOL_NAME, "version": report.tool_version},
        "findings": [_finding_payload(finding) for finding in findings],
        "suppressed": {"count": filtered.suppressed_count},
        "ignored": {"paths": [detail.to_dict() for detail in report.ignored_path_details]},
        "config": {"schemaOk": True, "error": None},
    }


def _filter_findings_for_hook(
    findings: tuple[Finding, ...],
    *,
    paths: tuple[str, ...],
    changed_ranges: str = "",
    base_stable_identities: frozenset[str] | None = None,
) -> _HookFilterResult:
    """Apply hook changed-region and new-only semantics to full-scan findings."""
    changed = _changed_region_set(findings, paths, changed_ranges)
    kept: list[Finding] = []
    suppressed_count = 0

    for finding in findings:
        scope = _scope_for_finding(finding)
        stable_identity = _hook_stable_identity(finding, scope)

        if changed.active:
            if scope in {"file", "project"}:
                if base_stable_identities is None or stable_identity in base_stable_identities:
                    suppressed_count += 1
                    continue
            elif not _is_finding_intersecting_changed_region(finding, changed):
                suppressed_count += 1
                continue

        if base_stable_identities is not None and stable_identity in base_stable_identities:
            continue

        kept.append(finding)

    return _HookFilterResult(findings=tuple(kept), suppressed_count=suppressed_count)


def _scope_for_finding(finding: Finding) -> str:
    """Classify a finding into the hook contract's closed scope enum."""
    if finding.line is None:
        return "project"
    if finding.rule_id in _FILE_SCOPE_RULE_IDS:
        return "file"
    if finding.symbol is not None:
        return "symbol"
    return "line"


def _hook_stable_identity(finding: Finding, scope: str | None = None) -> str:
    """Return hook identity stable across line shifts and measured-value changes."""
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


def stable_identities_from_baseline(path: Path) -> frozenset[str]:
    """Read stable identities from a hook, analysis, or baseline JSON file.

    Args:
        path: JSON file passed to `gruff-py hook --baseline`.

    Returns:
        Stable identities found in the file. Rows without `stableIdentity` are
        converted from their rule/file/scope-or-message fields when possible.

    Raises:
        ValueError: If the file cannot be read, is not valid JSON, or does not
            contain the expected top-level findings/entries array.
    """
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Unable to read baseline file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid baseline JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Baseline root must be a JSON object.")
    # A present-but-empty "findings": [] is a valid clean baseline, so test for
    # the key explicitly instead of `or` (which treats the empty list as absent
    # and would reject a baseline captured when the code had no findings).
    rows = payload.get("findings")
    if rows is None:
        rows = payload.get("entries")
    if not isinstance(rows, list):
        raise ValueError('Baseline must include a "findings" array.')
    identities = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        identity = row.get("stableIdentity")
        if isinstance(identity, str) and identity:
            identities.add(identity)
            continue
        fallback = _stable_identity_from_row(row)
        if fallback is not None:
            identities.add(fallback)
    return frozenset(identities)


def stable_identities_from_git_base(
    *,
    project_root: Path,
    paths: tuple[str, ...],
    diff_ref: str,
    config_path: Path | None,
    no_config: bool,
    include_ignored: bool,
) -> frozenset[str]:
    """Analyze the git base tree and return hook stable identities.

    Args:
        project_root: Git working tree where the hook command was invoked.
        paths: Requested hook paths to materialize from the base tree.
        diff_ref: Git ref supplied to `--diff`; `working-tree` maps to `HEAD`.
        config_path: Explicit config file from the hook CLI, when supplied.
        no_config: Whether config discovery is disabled.
        include_ignored: Whether default-ignored and gitignored paths are
            included in the base analysis.

    Returns:
        Hook stable identities present in the requested base tree.
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
            )
        )
        return frozenset(
            _hook_stable_identity(finding, _scope_for_finding(finding))
            for finding in report.findings
        )


def render_json(payload: dict[str, Any]) -> str:
    """Render a hook payload with the same indentation as JSON reports.

    Args:
        payload: JSON-serializable hook payload.

    Returns:
        Pretty-printed JSON terminated with a newline.
    """
    return json.dumps(payload, indent=4) + "\n"


def _finding_payload(finding: Finding) -> dict[str, Any]:
    scope = _scope_for_finding(finding)
    return {
        "ruleId": finding.rule_id,
        "pillar": finding.pillar.value,
        "severity": finding.severity.value,
        "scope": scope,
        "file": finding.file_path,
        "line": finding.line,
        "endLine": finding.end_line,
        "symbol": finding.symbol,
        "message": finding.message,
        "remediation": _remediation_for(finding),
        "metadata": _metadata_for(finding),
        "stableIdentity": _hook_stable_identity(finding, scope),
        "fingerprint": finding.fingerprint(),
    }


def _remediation_for(finding: Finding) -> str:
    if finding.remediation:
        return finding.remediation
    try:
        return documentation_for_rule(finding.rule_id).fix_guidance
    except KeyError:
        return "Review the finding and adjust the code or configuration deliberately."


def _metadata_for(finding: Finding) -> dict[str, Any]:
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
    for key in keys:
        if key in metadata:
            return metadata[key]
    return None


def _changed_region_set(
    findings: tuple[Finding, ...],
    paths: tuple[str, ...],
    changed_ranges: str,
) -> ChangedRegionSet:
    if not changed_ranges:
        return ChangedRegionSet(source="")
    source_paths = {
        *(path.replace("\\", "/").strip("/") for path in paths),
        *(finding.file_path for finding in findings),
    }
    return parse_explicit_ranges(
        tuple(sorted(path for path in source_paths if path)), changed_ranges
    )


def _is_finding_intersecting_changed_region(finding: Finding, changed: ChangedRegionSet) -> bool:
    if finding.line is None:
        return changed.is_file_changed(finding.file_path)
    end_line = (
        finding.end_line
        if finding.end_line is not None and finding.end_line >= finding.line
        else finding.line
    )
    return changed.has_changed_range(finding.file_path, finding.line, end_line)


def _stable_identity_from_row(row: dict[str, Any]) -> str | None:
    rule_id = row.get("ruleId")
    file_path = row.get("file", row.get("filePath"))
    if not isinstance(rule_id, str) or not isinstance(file_path, str):
        return None
    symbol = row.get("symbol")
    scope = row.get("scope")
    if isinstance(symbol, str) and symbol:
        payload: dict[str, Any] = {"ruleId": rule_id, "file": file_path, "symbol": symbol}
    elif scope in {"file", "project"}:
        payload = {"ruleId": rule_id, "file": file_path, "scope": scope}
    else:
        message = row.get("message", "")
        payload = {"ruleId": rule_id, "file": file_path, "message": message}
    return _stable_hash(payload)


def _stable_hash(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    encoded = encoded.replace("/", r"\/")
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _materialize_git_base(
    project_root: Path,
    target_root: Path,
    base_ref: str,
    paths: tuple[str, ...],
) -> None:
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
    output = _git_bytes(project_root, args).decode("utf-8", errors="replace")
    return [line for line in output.splitlines() if line]


def _git_bytes(project_root: Path, args: list[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_root), *args],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"unable to resolve git base for hook diff: {exc}") from exc
    return completed.stdout
