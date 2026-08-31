"""Manage the findings a user has deliberately accepted as existing debt.

CLI and API callers use this module when generating a baseline or hiding findings that match one.
It validates the shared baseline format and returns report metadata for the final analysis result.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gruffpy.analysis.schema import BASELINE_SCHEMA_VERSION
from gruffpy.finding.finding import Finding

DEFAULT_BASELINE_FILENAME = "gruff-baseline.json"
LEGACY_BASELINE_SCHEMA_VERSION = "gruff.baseline.v1"
ACCEPTED_BASELINE_SCHEMA_VERSIONS = frozenset({BASELINE_SCHEMA_VERSION, LEGACY_BASELINE_SCHEMA_VERSION})


class BaselineError(ValueError):
    """Explain why a requested baseline operation could not be completed.

    Callers surface this when a user selects a missing, invalid, unreadable, or unwritable file.
    It keeps file failures separate so analysis reports a diagnostic instead of accepted debt.
    """


@dataclass(frozen=True, slots=True)
class BaselineOptions:
    """Carry the user's baseline choices into the analysis pipeline.

    Use after CLI or API options select generation, application, or no baseline.
    The runner uses it to record, suppress, or leave findings unchanged.

    Attributes:
        apply_path: Explicit baseline to suppress matched findings, or ``None``
            to fall back to the conventional ``gruff-baseline.json``.
        generate_path: When set, write current findings to this path instead of
            applying a baseline; mutually exclusive with ``apply_path``.
        disabled: When true, skip both explicit and default baseline application.
    """

    apply_path: Path | None = None
    generate_path: Path | None = None
    disabled: bool = False


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """Represent one accepted finding stored in a baseline file.

    Use an entry when a live finding must be written or compared with previously accepted debt.
    Its compatibility fields preserve the identity that sibling gruff implementations also consume.

    Attributes:
        fingerprint: Cross-implementation finding fingerprint.
        rule_id: Rule that produced the finding.
        file_path: Project-relative source path the finding refers to.
        line: 1-based line number, or ``None`` for file-level findings.
        symbol: Symbol name attached to the finding, when applicable.
        message: Human-readable finding message captured at baseline time.
    """

    fingerprint: str
    rule_id: str
    file_path: str
    line: int | None
    symbol: str | None
    message: str

    @classmethod
    def from_finding(cls, finding: Finding) -> BaselineEntry:
        """Capture a live finding as an accepted baseline entry.

        Use while generating a baseline so a later run can recognise the same finding.

        Args:
            finding: Live finding whose identity will be recorded.

        Returns:
            Persisted entry that round-trips to the same baseline row.
        """
        return cls(
            fingerprint=finding.fingerprint(),
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            line=finding.line,
            symbol=finding.symbol,
            message=finding.message,
        )

    @classmethod
    def from_dict(cls, row: dict[str, Any], index: int) -> BaselineEntry:
        """Validate one stored row and restore its accepted finding identity.

        Use while loading; sibling and legacy file-path keys remain accepted for compatibility.

        Args:
            row: Raw JSON object from the ``findings`` array of a baseline file.
            index: Zero-based row position, used to make error messages locatable.

        Returns:
            Parsed entry ready for matching against live findings.

        Raises:
            BaselineError: When required keys are missing or have the wrong type.
        """
        fingerprint = _required_string(row, "fingerprint", index)
        rule_id = _required_string(row, "ruleId", index)
        file_path = _baseline_file_path(row, index)
        line = row.get("line")
        # File-level findings have no line; any other value prevents a safe baseline match.
        if line is not None and not isinstance(line, int):
            raise BaselineError(f'Baseline finding {index} field "line" must be an integer or null.')
        symbol = row.get("symbol")
        # Findings outside named symbols store null; malformed values cannot identify accepted debt.
        if symbol is not None and not isinstance(symbol, str):
            raise BaselineError(f'Baseline finding {index} field "symbol" must be a string or null.')
        message = row.get("message", "")
        # Older baselines may omit the display message, but a non-text value makes the file invalid.
        if not isinstance(message, str):
            raise BaselineError(f'Baseline finding {index} field "message" must be a string.')
        return cls(
            fingerprint=fingerprint,
            rule_id=rule_id,
            file_path=file_path,
            line=line,
            symbol=symbol,
            message=message,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return this accepted finding in the shared baseline row shape.

        Use when writing a baseline or exposing stale entries in an analysis report.

        Returns:
            JSON-ready row matching the schema written to baseline files.
        """
        return {
            "fingerprint": self.fingerprint,
            "ruleId": self.rule_id,
            "file": self.file_path,
            "line": self.line,
            "symbol": self.symbol,
            "message": self.message,
        }

    def key(self) -> tuple[str, str, str]:
        """Return the compatibility identity used to match a live finding.

        Use during application; loading rejects empty components before they reach this method.

        Returns:
            ``(fingerprint, rule_id, file_path)`` tuple, the canonical match key.
        """
        return (self.fingerprint, self.rule_id, self.file_path)


@dataclass(frozen=True, slots=True)
class BaselineData:
    """Bundle a baseline's display path with its accepted findings.

    The store returns this after a user loads or generates a baseline.
    The runner then uses the entries for matching and the path for user-facing report metadata.
    """

    path: str
    entries: tuple[BaselineEntry, ...]


@dataclass(frozen=True, slots=True)
class BaselineReport:
    """Describe what baseline handling changed in an analysis run.

    Reporters use this after generation or application to show the source, matches, and stale debt.
    Empty stale entries mean none were found or the scan was too narrow to judge them safely.

    Attributes:
        path: Display path for the baseline file as it appears in the report.
        generated: True when this run wrote the baseline; False when it applied one.
        total_entries: Number of entries persisted in (or matched against) the baseline.
        suppressed_findings: Live findings hidden by matching baseline entries.
        stale_evaluation: Scope used to judge stale entries
            (``generated``/``full-project``/``partial-scope``).
        stale_entries: Entries that no longer match any live finding.
        source: ``explicit`` when the path came from a flag, ``default`` when auto-loaded.
    """

    path: str
    generated: bool
    total_entries: int
    suppressed_findings: int
    stale_evaluation: str
    stale_entries: tuple[BaselineEntry, ...] = ()
    source: str = "explicit"

    def to_dict(self) -> dict[str, Any]:
        """Return baseline results in the stable analysis-report extension shape.

        Use when a reporter needs JSON-ready counts, source details, and stale entries for the user.

        Returns:
            JSON-ready dict matching the ``baseline`` field of analysis reports.
        """
        return {
            "path": self.path,
            "generated": self.generated,
            "totalEntries": self.total_entries,
            "suppressedFindings": self.suppressed_findings,
            "staleEvaluation": self.stale_evaluation,
            "staleEntries": len(self.stale_entries),
            "source": self.source,
            "stale": [entry.to_dict() for entry in self.stale_entries],
        }


@dataclass(frozen=True, slots=True)
class BaselineApplyResult:
    """Carry visible findings and baseline effects back to the runner.

    Use after baseline matching so the user sees new findings separately from accepted debt.
    An empty findings list means every live finding matched the baseline or the scan found none.
    """

    findings: list[Finding]
    report: BaselineReport


class BaselineStore:
    """Read and write a user's baseline relative to the analysed project.

    Use this at the file boundary after the caller has selected a baseline path.
    It validates reads and writes atomically so a failed update does not leave a partial baseline.
    """

    def __init__(self, project_root: str | Path) -> None:
        """Anchor baseline paths to the project being analysed.

        Use one store per run; the requested operation validates an empty path after resolution.
        """
        self._project_root = Path(project_root)

    def read(self, path: str | Path) -> BaselineData:
        """Load accepted findings from the baseline selected by the user.

        Use before suppression; an empty or missing path becomes a clear baseline diagnostic.

        Args:
            path: Baseline location relative to the project root (or absolute).

        Returns:
            Parsed baseline data with entries ready to match against findings.

        Raises:
            BaselineError: When the file is missing, unreadable, malformed JSON,
                or has an unrecognised ``schemaVersion``.
        """
        display_path = _display_path(path)
        absolute_path = self._absolute_path(path)
        # A missing file cannot suppress debt, so the user gets an error instead of a clean run.
        if not absolute_path.is_file():
            raise BaselineError(f"Baseline file not found: {display_path}")
        try:
            payload = json.loads(absolute_path.read_text(encoding="utf-8"))
        # For example, permissions may change after a user selects a file with --baseline-path.
        except OSError as exc:
            raise BaselineError(f"Unable to read baseline file: {display_path}") from exc
        # For example, an editor may have saved the selected baseline in a non-UTF-8 encoding.
        except UnicodeDecodeError as exc:
            raise BaselineError(f"Baseline file is not valid UTF-8: {display_path}") from exc
        # For example, a hand-edited baseline may have a trailing comma or unfinished object.
        except json.JSONDecodeError as exc:
            raise BaselineError(f"Invalid baseline JSON: {exc.msg}") from exc
        # A non-object document has no schema or finding collection the user can apply.
        if not isinstance(payload, dict):
            raise BaselineError("Baseline root must be a JSON object.")
        schema = payload.get("schemaVersion")
        # Missing or unknown schema text cannot be interpreted compatibly across gruff tools.
        if schema not in ACCEPTED_BASELINE_SCHEMA_VERSIONS:
            accepted = ", ".join(f'"{v}"' for v in sorted(ACCEPTED_BASELINE_SCHEMA_VERSIONS))
            raise BaselineError(f"Baseline schemaVersion must be one of: {accepted}.")
        return BaselineData(
            path=_report_path(self._project_root, path, absolute_path),
            entries=_entries_from_payload(payload),
        )

    def write(self, path: str | Path, findings: list[Finding]) -> BaselineData:
        """Record the current findings in the baseline destination the user chose.

        Use for generation; no findings creates a valid baseline with no accepted debt.

        Args:
            path: Destination relative to the project root (or absolute).
            findings: Findings whose identities will be persisted as entries.

        Returns:
            ``BaselineData`` describing the file just written.

        Raises:
            BaselineError: When the file or its parent directory cannot be written.
        """
        # Preserve every finding so the generated file represents exactly what the user accepted.
        entries = tuple(BaselineEntry.from_finding(finding) for finding in findings)
        absolute_path = self._absolute_path(path)
        try:
            absolute_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schemaVersion": BASELINE_SCHEMA_VERSION,
                "generatedAt": datetime.now(UTC).isoformat(),
                "findings": [entry.to_dict() for entry in entries],
            }
            text = json.dumps(payload, indent=4) + "\n"
            _atomic_write_text(absolute_path, text)
        # For example, a read-only project can prevent --generate-baseline replacing the file.
        except OSError as exc:
            raise BaselineError(f"Unable to write baseline file: {_display_path(path)}") from exc
        return BaselineData(path=_report_path(self._project_root, path, absolute_path), entries=entries)

    def _absolute_path(self, path: str | Path) -> Path:
        """Resolve a selected baseline path against this analysis project.

        Use before file access; absolute paths remain unchanged and empty paths resolve to the root.
        """
        candidate = Path(path)
        # An absolute selection already identifies the user's file inside or outside the project.
        if candidate.is_absolute():
            return candidate
        return self._project_root / candidate


def generate_baseline(
    *,
    project_root: str | Path,
    path: str | Path,
    findings: list[Finding],
) -> BaselineReport:
    """Persist the current findings as the user's accepted debt.

    Use for generation; findings stay visible while the report confirms what was written.

    Args:
        project_root: Resolved project root used for display-path normalisation.
        path: Destination baseline file (relative or absolute).
        findings: Findings to record as the new baseline.

    Returns:
        Report describing the just-written baseline.
    """
    data = BaselineStore(project_root).write(path, findings)
    return BaselineReport(
        path=data.path,
        generated=True,
        total_entries=len(data.entries),
        suppressed_findings=0,
        stale_evaluation="generated",
        source=_baseline_source(path),
    )


def apply_baseline(
    *,
    project_root: str | Path,
    path: str | Path,
    findings: list[Finding],
    source: str,
    scan_scope: str = "full-project",
) -> BaselineApplyResult:
    """Separate accepted debt from findings the user still needs to review.

    Use after analysis; partial scans deliberately leave stale-debt status unknown.

    Args:
        project_root: Resolved project root used for display-path normalisation.
        path: Baseline file to read.
        findings: Live findings to filter against the baseline.
        source: Origin label recorded on the resulting report (``explicit``/``default``).
        scan_scope: ``full-project`` when the current run scanned the whole
            project, ``partial-scope`` when paths narrowed the scan. Partial
            scans skip stale-entry reporting because an unmatched baseline row
            could simply belong to a file the current scan did not visit.

    Returns:
        Filtered findings plus baseline report metadata.
    """
    baseline = BaselineStore(project_root).read(path)
    entries_by_key = {entry.key(): entry for entry in baseline.entries}
    matched_keys: set[tuple[str, str, str]] = set()
    filtered: list[Finding] = []
    suppressed = 0

    # Compare every finding so the user receives unmatched work and an accepted-debt count.
    for finding in findings:
        key = (finding.fingerprint(), finding.rule_id, finding.file_path)
        # A compatible identity means this debt was accepted and should not appear as new work.
        if key in entries_by_key:
            matched_keys.add(key)
            suppressed += 1
            continue
        filtered.append(finding)

    # Only a full scan proves unmatched debt is stale rather than simply outside the paths the caller asked for.
    stale = tuple(entry for entry in baseline.entries if entry.key() not in matched_keys) if scan_scope == "full-project" else ()
    return BaselineApplyResult(
        findings=filtered,
        report=BaselineReport(
            path=baseline.path,
            generated=False,
            total_entries=len(baseline.entries),
            suppressed_findings=suppressed,
            stale_evaluation=scan_scope,
            stale_entries=stale,
            source=source,
        ),
    )


def default_baseline_path(project_root: str | Path) -> Path:
    """Locate the conventional baseline for the project a user is analysing.

    Use when no explicit path was supplied; an empty project follows normal ``Path`` resolution.

    Args:
        project_root: Project root that anchors the default baseline filename.

    Returns:
        Absolute path to the conventional ``gruff-baseline.json`` location.
    """
    return Path(project_root) / DEFAULT_BASELINE_FILENAME


def _entries_from_payload(payload: dict[str, Any]) -> tuple[BaselineEntry, ...]:
    """Restore all accepted finding rows from a validated baseline object.

    Use while loading; a missing modern key falls back to the legacy collection.
    No collection means the selected baseline is invalid.
    """
    rows = payload.get("findings")
    # Sibling or older baselines may use ``entries``; accepting it keeps existing debt portable.
    if rows is None:
        rows = payload.get("entries")
    # Without a list of rows there is no deterministic collection of accepted findings to apply.
    if not isinstance(rows, list):
        raise BaselineError('Baseline key "findings" (or legacy "entries") must be a list.')

    entries: list[BaselineEntry] = []
    # Validate every stored finding so malformed debt cannot silently hide the wrong result.
    for index, row in enumerate(rows):
        # Each accepted finding must be an object containing the compatibility identity fields.
        if not isinstance(row, dict):
            raise BaselineError(f"Baseline finding {index} must be a JSON object.")
        entries.append(BaselineEntry.from_dict(row, index))
    return tuple(entries)


def _required_string(row: dict[str, Any], key: str, index: int) -> str:
    """Read a non-empty compatibility field from one baseline row.

    Use while loading; absent, empty, or non-text values report the row a user must fix.
    """
    value = row.get(key)
    # Empty identity text cannot match a real finding, so the selected baseline is invalid.
    if not isinstance(value, str) or value == "":
        raise BaselineError(f'Baseline finding {index} must include non-empty "{key}".')
    return value


def _baseline_file_path(row: dict[str, Any], index: int) -> str:
    """Read the portable source path from a modern or legacy baseline row.

    Use while loading sibling baselines; missing paths cannot identify the file owning the debt.
    """
    value = row.get("file")
    # Older producers used ``filePath``; retaining it keeps shared baselines compatible.
    if value is None:
        value = row.get("filePath")
    # A finding without a usable file path cannot be matched and must be corrected.
    if not isinstance(value, str) or value == "":
        raise BaselineError(f'Baseline finding {index} must include non-empty "file" (or legacy "filePath").')
    return value


def _atomic_write_text(path: Path, text: str) -> None:
    """Replace a baseline only after its complete JSON text reaches disk.

    Use for generation so an interrupted or failed write leaves the user's previous baseline intact.
    """
    fd, staging_path = tempfile.mkstemp(prefix="gruff-baseline-", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging_path, path)
    # For example, a full disk can fail after staging; remove the partial and keep the original.
    except Exception:
        # Cleanup failure must not hide the write error the user needs to act on.
        with suppress(OSError):
            os.unlink(staging_path)
        raise


def _display_path(path: str | Path) -> str:
    """Render a baseline path consistently in reports and diagnostics.

    Use for output; empty input stays empty so the caller can describe the missing selection.
    """
    return str(path).replace("\\", "/")


def _report_path(project_root: Path, requested: str | Path, absolute_path: Path) -> str:
    """Choose the shortest stable baseline path to show in analysis output.

    Use after file access; relative selections stay relative and external paths stay absolute.
    """
    requested_path = Path(requested)
    # A user-entered relative path is already the project-oriented label they expect in the report.
    if not requested_path.is_absolute():
        return _display_path(requested)
    try:
        return _display_path(absolute_path.relative_to(project_root))
    # For example, an external baseline cannot be displayed relative to this project root.
    except ValueError:
        return _display_path(absolute_path)


def _baseline_source(path: str | Path) -> str:
    """Label whether the user selected a path or gruff found the default.

    Use in report metadata; empty paths count as explicit because they are not the default name.
    """
    return "default" if Path(path).name == DEFAULT_BASELINE_FILENAME else "explicit"
