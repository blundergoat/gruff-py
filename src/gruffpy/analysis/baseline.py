"""Read, write, and apply gruff finding baselines."""

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
ACCEPTED_BASELINE_SCHEMA_VERSIONS = frozenset(
    {BASELINE_SCHEMA_VERSION, LEGACY_BASELINE_SCHEMA_VERSION}
)


class BaselineError(ValueError):
    """Raised when a baseline file cannot be read, parsed, or written."""


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One persisted finding identity used for baseline suppression."""

    fingerprint: str
    rule_id: str
    file_path: str
    line: int | None
    symbol: str | None
    message: str

    @classmethod
    def from_finding(cls, finding: Finding) -> BaselineEntry:
        """Build a baseline entry from a live finding."""
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
        """Parse a baseline row, accepting Python and sibling baseline key names."""
        fingerprint = _required_string(row, "fingerprint", index)
        rule_id = _required_string(row, "ruleId", index)
        file_path = _baseline_file_path(row, index)
        line = row.get("line")
        if line is not None and not isinstance(line, int):
            raise BaselineError(
                f'Baseline finding {index} field "line" must be an integer or null.'
            )
        symbol = row.get("symbol")
        if symbol is not None and not isinstance(symbol, str):
            raise BaselineError(
                f'Baseline finding {index} field "symbol" must be a string or null.'
            )
        message = row.get("message", "")
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
        """Serialise the entry to the ``gruff-py.baseline.v1`` row shape."""
        return {
            "fingerprint": self.fingerprint,
            "ruleId": self.rule_id,
            "file": self.file_path,
            "line": self.line,
            "symbol": self.symbol,
            "message": self.message,
        }

    def key(self) -> tuple[str, str, str]:
        """Return the exact identity tuple used to match live findings."""
        return (self.fingerprint, self.rule_id, self.file_path)


@dataclass(frozen=True, slots=True)
class BaselineData:
    """Loaded or generated baseline entries."""

    path: str
    entries: tuple[BaselineEntry, ...]


@dataclass(frozen=True, slots=True)
class BaselineReport:
    """Report metadata describing baseline generation or suppression."""

    path: str
    generated: bool
    total_entries: int
    suppressed_findings: int
    stale_evaluation: str
    stale_entries: tuple[BaselineEntry, ...] = ()
    source: str = "explicit"

    def to_dict(self) -> dict[str, Any]:
        """Serialise baseline metadata into the analysis report extension."""
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
    """Filtered findings plus report metadata after applying a baseline."""

    findings: list[Finding]
    report: BaselineReport


class BaselineStore:
    """Reads and writes baseline files relative to a project root."""

    def __init__(self, project_root: str | Path) -> None:
        self._project_root = Path(project_root)

    def read(self, path: str | Path) -> BaselineData:
        """Read and validate a baseline file."""
        display_path = _display_path(path)
        absolute = self._absolute_path(path)
        if not absolute.is_file():
            raise BaselineError(f"Baseline file not found: {display_path}")
        try:
            payload = json.loads(absolute.read_text())
        except OSError as exc:
            raise BaselineError(f"Unable to read baseline file: {display_path}") from exc
        except json.JSONDecodeError as exc:
            raise BaselineError(f"Invalid baseline JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise BaselineError("Baseline root must be a JSON object.")
        schema = payload.get("schemaVersion")
        if schema not in ACCEPTED_BASELINE_SCHEMA_VERSIONS:
            raise BaselineError(f'Baseline schemaVersion must be "{BASELINE_SCHEMA_VERSION}".')
        return BaselineData(
            path=_report_path(self._project_root, path, absolute),
            entries=_entries_from_payload(payload),
        )

    def write(self, path: str | Path, findings: list[Finding]) -> BaselineData:
        """Write *findings* to a baseline file atomically."""
        entries = tuple(BaselineEntry.from_finding(finding) for finding in findings)
        absolute = self._absolute_path(path)
        try:
            absolute.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schemaVersion": BASELINE_SCHEMA_VERSION,
                "generatedAt": datetime.now(UTC).isoformat(),
                "findings": [entry.to_dict() for entry in entries],
            }
            text = json.dumps(payload, indent=4) + "\n"
            _atomic_write_text(absolute, text)
        except OSError as exc:
            raise BaselineError(f"Unable to write baseline file: {_display_path(path)}") from exc
        return BaselineData(path=_report_path(self._project_root, path, absolute), entries=entries)

    def _absolute_path(self, path: str | Path) -> Path:
        candidate = Path(path)
        if candidate.is_absolute():
            return candidate
        return self._project_root / candidate


def generate_baseline(
    *,
    project_root: str | Path,
    path: str | Path,
    findings: list[Finding],
) -> BaselineReport:
    """Persist current findings as accepted debt without suppressing them."""
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
) -> BaselineApplyResult:
    """Suppress findings that match entries in *path*."""
    baseline = BaselineStore(project_root).read(path)
    entries_by_key = {entry.key(): entry for entry in baseline.entries}
    matched_keys: set[tuple[str, str, str]] = set()
    filtered: list[Finding] = []
    suppressed = 0

    for finding in findings:
        key = (finding.fingerprint(), finding.rule_id, finding.file_path)
        if key in entries_by_key:
            matched_keys.add(key)
            suppressed += 1
            continue
        filtered.append(finding)

    stale = tuple(entry for entry in baseline.entries if entry.key() not in matched_keys)
    return BaselineApplyResult(
        findings=filtered,
        report=BaselineReport(
            path=baseline.path,
            generated=False,
            total_entries=len(baseline.entries),
            suppressed_findings=suppressed,
            stale_evaluation="full-project",
            stale_entries=stale,
            source=source,
        ),
    )


def default_baseline_path(project_root: str | Path) -> Path:
    """Return the conventional project-root baseline path."""
    return Path(project_root) / DEFAULT_BASELINE_FILENAME


def _entries_from_payload(payload: dict[str, Any]) -> tuple[BaselineEntry, ...]:
    rows = payload.get("findings")
    if rows is None:
        rows = payload.get("entries")
    if not isinstance(rows, list):
        raise BaselineError('Baseline key "findings" must be a list.')

    entries: list[BaselineEntry] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise BaselineError(f"Baseline finding {index} must be a JSON object.")
        entries.append(BaselineEntry.from_dict(row, index))
    return tuple(entries)


def _required_string(row: dict[str, Any], key: str, index: int) -> str:
    value = row.get(key)
    if not isinstance(value, str) or value == "":
        raise BaselineError(f'Baseline finding {index} must include non-empty "{key}".')
    return value


def _baseline_file_path(row: dict[str, Any], index: int) -> str:
    value = row.get("file")
    if value is None:
        value = row.get("filePath")
    if not isinstance(value, str) or value == "":
        raise BaselineError(f'Baseline finding {index} must include non-empty "file".')
    return value


def _atomic_write_text(path: Path, text: str) -> None:
    fd, temp_path = tempfile.mkstemp(prefix="gruff-baseline-", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except Exception:
        with suppress(OSError):
            os.unlink(temp_path)
        raise


def _display_path(path: str | Path) -> str:
    return str(path).replace("\\", "/")


def _report_path(project_root: Path, requested: str | Path, absolute: Path) -> str:
    requested_path = Path(requested)
    if not requested_path.is_absolute():
        return _display_path(requested)
    try:
        return _display_path(absolute.relative_to(project_root))
    except ValueError:
        return _display_path(absolute)


def _baseline_source(path: str | Path) -> str:
    return "default" if Path(path) == Path(DEFAULT_BASELINE_FILENAME) else "explicit"
