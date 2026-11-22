"""Reconcile a fresh scan against the debt a user already reviewed, so only genuinely new problems stop the run.

This is the engine behind ``gruff-py analyse --baseline gruff-baseline.json``. A baseline row stores one
line-free identity and a count and nothing positional, so everyday reformatting never re-flags accepted debt,
while a second occurrence beyond the reviewed count is still reported as new.

Sensitive-data findings are counted here and never stored: withholding their identity is what stops a durable
review from hiding a secret. A 0.5 baseline is refused with the command that carries its reviews forward.
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gruffpy.analysis.schema import BASELINE_SCHEMA_VERSION, LEGACY_BASELINE_SCHEMA_VERSIONS
from gruffpy.finding.baseline_identity import (
    TOOL_LANGUAGE,
    BaselineIdentityError,
    FindingIdentity,
    finding_identities,
    is_baseline_eligible,
    normalise_measured_values,
)
from gruffpy.finding.finding import Finding

DEFAULT_BASELINE_FILENAME = "gruff-baseline.json"

_FORBIDDEN_OCCURRENCE_KEYS = ("line", "endLine", "column", "message", "severity", "confidence")
"""Keys a v3 row may never carry; each one is a way a stored baseline could expire on an edit or leak a finding's text."""

_SENSITIVE_INELIGIBILITY_REASON = (
    "Sensitive findings are never baselinable; they are counted here and stay visible until fixed or excluded with a reason."
)

_UNLOCATED_SPEND_LINE = 2**31
"""Where a finding with no line sorts when a reviewed count is spent, so an unlocated occurrence is always spent last."""

_LEGACY_ROW_CONTAINERS = ("findings", "groups", "entries")
"""The three keys the five 0.5 writers used for their row list; a file naming two of them cannot be read alike twice."""


class BaselineError(ValueError):
    """Explain why a requested baseline operation could not be completed.

    Callers surface this when a user selects a missing, invalid, unreadable, or unwritable file.
    It keeps file failures separate so analysis reports a diagnostic instead of silently accepted debt.
    """


@dataclass(frozen=True, slots=True)
class BaselineOptions:
    """Record the baseline operation requested on the command line.

    The runner uses these choices before scoring and exit checks.
    Ordinary scans can apply reviewed findings. Generation and migration write a separate result for review.

    Attributes:
        apply_path: Explicit baseline to apply, or ``None`` to fall back to the conventional ``gruff-baseline.json``.
        generate_path: When set, write current findings to this path instead of applying a baseline.
        disabled: When true, skip both explicit and default baseline application.
        migrate_path: 0.5 baseline whose reviews are carried into ``generate_path``, leaving the original untouched;
            ``None`` is the ordinary case, where generation records the current findings and carries nothing across.
        force_overwrite: When true, a generate at the shared default path may overwrite a 0.5 baseline instead of
            refusing; false is the safe default, which keeps the user's retreat path intact.
    """

    apply_path: Path | None = None
    generate_path: Path | None = None
    disabled: bool = False
    migrate_path: Path | None = None
    force_overwrite: bool = False


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One reviewed row of the user's committed ``gruff-baseline.json``: a line-free identity and a count.

    Matching reads the identity and the count and nothing else; the rule, path, and subject are kept only so a
    reviewer can read the file. Because no line, message, or severity is stored, reformatting never re-flags debt.

    Attributes:
        identity: 16 lowercase hex characters; the only field matching reads.
        count: Occurrences the team accepted, at least one; an extra occurrence beyond it surfaces as new.
        rule_id: Descriptive rule id for readers; empty when the row was hand-written without one.
        path: Descriptive project-relative path; empty when the row omits it.
        subject: Descriptive identity subject, so a reviewer sees what was reviewed; empty when the row omits it.
    """

    identity: str
    count: int
    rule_id: str = ""
    path: str = ""
    subject: str = ""

    @classmethod
    def from_dict(cls, row: dict[str, Any], index: int) -> BaselineEntry:
        """Restore a reviewed occurrence for durable matching while rejecting legacy position, message and classification fields.

        Args:
            row: Decoded occurrence with an identity and count for matching and optional ruleId, path and subject labels.
            index: Zero-based position, named in the error so the user can find the row.

        Returns:
            Validated entry ready to match against live findings. Missing or non-string labels become empty strings.

        Raises:
            BaselineError: When identity is not 16 lowercase hex characters, count is not a positive non-boolean integer,
                or a forbidden key is present.
        """
        identity = row.get("identity")
        # Reject malformed identities so a bad row cannot silently fail to match a reviewed finding.
        if not isinstance(identity, str) or len(identity) != 16 or any(character not in "0123456789abcdef" for character in identity):
            raise BaselineError(f"Baseline occurrences[{index}].identity must be 16 lowercase hex characters.")

        count = row.get("count")
        # A reviewed row with a count below one would suppress no findings.
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise BaselineError(f"Baseline occurrences[{index}].count must be a positive integer.")

        # Position, message and classification fields are rejected so a stored review depends on its durable identity and count.
        for forbidden in _FORBIDDEN_OCCURRENCE_KEYS:
            if forbidden in row:
                raise BaselineError(f'Baseline occurrences[{index}] carries forbidden key "{forbidden}".')

        return cls(
            identity=identity,
            count=count,
            rule_id=_optional_text(row, "ruleId"),
            path=_optional_text(row, "path"),
            subject=_optional_text(row, "subject"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Flatten the row into the JSON object a generated baseline writes, omitting empty descriptive fields.

        Returns:
            Identity and count first, then whichever descriptive fields the row actually carries.
        """
        row: dict[str, Any] = {"identity": self.identity, "count": self.count}
        # Descriptive fields are for readers only, so an absent one is left out rather than written as an empty string.
        for key, text in (("ruleId", self.rule_id), ("path", self.path), ("subject", self.subject)):
            if text:
                row[key] = text
        return row


@dataclass(frozen=True, slots=True)
class BaselineData:
    """A baseline file as read or written: where it lives, who wrote it, what it accepted, and what it only counted.

    The store returns this after a user loads or generates a baseline. Matching uses the entries, the report uses
    the path, and the sensitive counts explain the secrets the file deliberately did not store.

    Attributes:
        path: Display path for the baseline as it appears in the report.
        tool_language: Port that wrote the file; a foreign value is refused rather than applied.
        entries: Reviewed rows in ascending identity order.
        sensitive_by_rule: Sensitive findings counted at write time, keyed by rule id; empty when the scan found none.
    """

    path: str
    tool_language: str
    entries: tuple[BaselineEntry, ...]
    sensitive_by_rule: dict[str, int] = field(default_factory=dict)

    def by_identity(self) -> dict[str, BaselineEntry]:
        """Index the reviewed rows for matching.

        Returns:
            Rows keyed by identity, keeping the last row for a duplicate identity; empty when there are no entries.
        """
        return {entry.identity: entry for entry in self.entries}

    def sensitive_total(self) -> int:
        """Total the per-rule counts recorded without storing sensitive finding details.

        Returns:
            Total of the recorded counts across all rules, or zero when no counts are available.
        """
        return sum(self.sensitive_by_rule.values())


@dataclass(frozen=True, slots=True)
class BaselineCollision:
    """One identity that covers two declarations, so neither of them can be hidden.

    The run reports it by name and suppresses nothing: hiding either would let one review cover a finding nobody
    read. A user meets this when two same-named declarations in one file cannot be told apart.

    Attributes:
        identity: The identity both declarations produced.
        rule_id: Rule that emitted them.
        path: File they share.
        subjects: The colliding subjects, so the user can see which declarations were confused.
    """

    identity: str
    rule_id: str
    path: str
    subjects: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BaselineReport:
    """Describe what baseline handling changed in one analysis run.

    Reporters use this after generation, migration, or application to show the source, what was hidden, and what
    the user has since fixed. Empty stale entries mean none were found or the scan was too narrow to judge them.

    Attributes:
        path: Display path for the baseline file as it appears in the report.
        generated: True when this run wrote the baseline; False when it applied one.
        total_entries: Rows persisted in, or matched against, the baseline.
        suppressed_findings: Live findings hidden because the user had already reviewed them.
        stale_evaluation: Scope used to judge resolved debt (``generated``/``migrated``/``full-project``/``partial-scope``).
        stale_entries: Reviewed rows with fewer live occurrences than reviewed, which is debt the user has since fixed.
        source: ``explicit`` when the path came from a flag, ``default`` when it was discovered.
        new_count: Findings absent from the baseline or beyond its count; these still fail the run.
        unchanged_count: Findings within the reviewed count, hidden from the failing set.
        absent_count: Reviewed occurrences no longer present, summed across the stale rows.
        collision_count: Findings whose identity could not separate two declarations; reported, never hidden.
        not_eligible_count: Findings with no identity, which no row may hide: sensitive findings, and findings whose
            symbol carries the ordinal separator.
        sensitive_counted: Sensitive findings a generated baseline counted rather than stored; 0 on an apply run.
    """

    path: str
    generated: bool
    total_entries: int
    suppressed_findings: int
    stale_evaluation: str
    stale_entries: tuple[BaselineEntry, ...] = ()
    source: str = "explicit"
    new_count: int = 0
    unchanged_count: int = 0
    absent_count: int = 0
    collision_count: int = 0
    not_eligible_count: int = 0
    sensitive_counted: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return baseline results in the canonical analysis-report shape.

        Returns:
            JSON-ready dict for the ``baseline`` section, with the resolved rows under ``stale``.
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
    """Return the findings that remain after applying reviewed counts.

    The analysis runner sends those findings to scoring and reporting.
    It can also enforce `--fail-on-new` using the classifications recorded here.

    Attributes:
        findings: The gated set: new, collided, and sensitive findings, in scan order.
        report: What moved, for the reporters.
        collisions: Identities that covered two declarations; each becomes a diagnostic the user reads.
        statuses: Classification keyed by the original finding object's identity.
    """

    findings: list[Finding]
    report: BaselineReport
    collisions: tuple[BaselineCollision, ...] = ()
    statuses: dict[int, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class BaselineMigration:
    """What ``--migrate-baseline`` wrote, so the command can tell the user what carried across.

    The 0.5 input is never touched; its reviewed findings are re-identified from the current scan and written to
    the new path, which leaves the original as the user's way back if the migration turns out wrong.

    Attributes:
        written_baseline: The v3 baseline as written.
        accepted: Current findings the 0.5 rows covered, before sensitive ones were set aside.
        sensitive_counted: Accepted findings that were sensitive and therefore counted rather than stored.
    """

    written_baseline: BaselineData
    accepted: int
    sensitive_counted: int


class BaselineStore:
    """Read and write a user's baseline relative to the analysed project.

    Use one store per run, at the file boundary, after the caller has chosen a path. Reads are validated and
    writes are atomic, so a failed update never leaves a half-written baseline behind.
    """

    def __init__(self, project_root: str | Path) -> None:
        """Anchor baseline paths to the project being analysed.

        Args:
            project_root: Project directory used to anchor relative baseline paths.

        Returns:
            None.
        """
        self._project_root = Path(project_root)

    def read(self, path: str | Path) -> BaselineData:
        """Load the reviewed findings from the selected baseline file.
        Use this before suppressing findings or replacing the default baseline so an unreadable or incompatible file can be reported safely.

        Args:
            path: Baseline location relative to the project root, or absolute.

        Returns:
            Parsed baseline ready to match against this run's findings.

        Raises:
            BaselineError: When the file is missing, unreadable, malformed, or uses an unsupported schema.
        """
        display_path = _display_path(path)
        payload = self._decode(path)

        schema = payload.get("schemaVersion")
        # A 0.5 file fails closed and names the command that carries its reviews forward, so nothing is silently dropped.
        if isinstance(schema, str) and schema in LEGACY_BASELINE_SCHEMA_VERSIONS:
            raise BaselineError(
                f'Baseline schema "{schema}" is a 0.5 baseline. Migrate it to a separate file with '
                f"`gruff-py analyse --migrate-baseline {display_path} --generate-baseline=<new path>`; the original is preserved."
            )
        # Unsupported or missing schemas are refused; the diagnostic points older files to the migration command.
        if schema != BASELINE_SCHEMA_VERSION:
            raise BaselineError(
                f'Baseline schemaVersion must be "{BASELINE_SCHEMA_VERSION}"; carry an older file\'s reviews forward '
                f"with `gruff-py analyse --migrate-baseline {display_path} --generate-baseline=<new path>`, "
                "which leaves the original untouched."
            )

        tool_language = payload.get("toolLanguage")
        # Missing or empty writer names are refused; apply_baseline separately checks whether the named port matches this run.
        if not isinstance(tool_language, str) or not tool_language:
            raise BaselineError("Baseline toolLanguage must name the port that wrote the file.")

        return BaselineData(
            path=_report_path(self._project_root, path, self._absolute_path(path)),
            tool_language=tool_language,
            entries=_entries_from_payload(payload),
            sensitive_by_rule=_sensitive_counts_from_payload(payload),
        )

    def write(
        self,
        path: str | Path,
        findings: Sequence[Finding],
        declaration_position: Callable[[Finding], int] | None = None,
    ) -> BaselineData:
        """Record the current findings as the debt the user accepts.

        Args:
            path: Destination relative to the project root, or absolute.
            findings: Scan findings to record. Sensitive findings contribute only counts by rule. Other findings with # in their symbols are skipped.
            declaration_position: Declaration resolver from the runner; ``None`` ranks by line, as a direct API call does.

        Returns:
            Baseline data for the written file, including its display path, reviewed entries, and recorded sensitive counts.

        Raises:
            BaselineError: When identity construction fails or the baseline file cannot be written.
        """
        data = _document_from_findings(findings, declaration_position)
        absolute_path = self._absolute_path(path)
        try:
            absolute_path.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_text(absolute_path, json.dumps(_document_payload(data), indent=4) + "\n")
        # For example, a read-only checkout can stop --generate-baseline replacing the file.
        except OSError as exc:
            raise BaselineError(f"Unable to write baseline file: {_display_path(path)}") from exc
        return BaselineData(
            path=_report_path(self._project_root, path, absolute_path),
            tool_language=TOOL_LANGUAGE,
            entries=data.entries,
            sensitive_by_rule=data.sensitive_by_rule,
        )

    def migrate(
        self,
        input_path: str | Path,
        output_path: str | Path,
        findings: Sequence[Finding],
        declaration_position: Callable[[Finding], int] | None = None,
    ) -> BaselineMigration:
        """Carry a 0.5 baseline's reviews into a new v3 file, leaving the original byte-identical.

        The reviews are re-identified from the current scan rather than translated, because a 0.5 digest names a
        line and this one does not. A finding the 0.5 file never accepted stays visible.

        Args:
            input_path: The 0.5 baseline to read; it is never written to, renamed, or deleted.
            output_path: Where the migrated v3 baseline is written; it must be a different file.
            findings: This run's findings, the only source of the new identities.
            declaration_position: Declaration resolver from the runner; ``None`` ranks by line.

        Returns:
            The written baseline, the number of findings accepted by the 0.5 baseline, and the number of sensitive findings tallied.

        Raises:
            BaselineError: When the input cannot be read or is not a 0.5 baseline, the paths name one file, writing fails,
                or the input bytes change during migration.
        """
        absolute_input = self._absolute_path(input_path)
        self._require_distinct_paths(absolute_input, self._absolute_path(output_path))
        original_bytes = _read_bytes(absolute_input, _display_path(input_path))
        accepted = _accepted_by_legacy(self._read_legacy(input_path, original_bytes), findings)
        written = self.write(output_path, accepted, declaration_position)

        # The 0.5 file is the user's way back, so the migration proves it survived rather than assuming it did.
        if _read_bytes(absolute_input, _display_path(input_path)) != original_bytes:
            raise BaselineError(f"Migration changed its own input: {_display_path(input_path)}")

        return BaselineMigration(written_baseline=written, accepted=len(accepted), sensitive_counted=written.sensitive_total())

    def _read_legacy(self, path: str | Path, contents: bytes) -> tuple[dict[str, Any], ...]:
        """Read the reviewed rows from a 0.5 baseline selected for migration.
        Use this when the user supplies `--migrate-baseline` so ambiguous or damaged rows stop the conversion before anything is written.

        Args:
            path: The migration input as the user named it; it is only used to name the file in errors, because the bytes are already read.
            contents: Raw bytes of the 0.5 baseline, the same bytes the migration later compares to prove the input was not changed.

        Returns:
            Rows from the file's single container in file order. An empty container gives an empty tuple.

        Raises:
            BaselineError: When the bytes are not UTF-8 or valid JSON, the root is not an object or its schemaVersion is not a 0.5 version, more than
                one of findings, groups and entries is a list, none is, or a row is not an object.
        """
        try:
            payload = json.loads(contents.decode("utf-8"))
        # For example, a hand-edited 0.5 baseline may carry a trailing comma the decoder rejects.
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BaselineError(f"Invalid baseline JSON: {_display_path(path)}") from exc
        # A JSON array can be readable while still lacking the baseline version migration requires.
        schema = payload.get("schemaVersion") if isinstance(payload, dict) else None
        # Refuse a v3 file here because it already has the identity scheme migration would generate.
        if not isinstance(schema, str) or schema not in LEGACY_BASELINE_SCHEMA_VERSIONS:
            raise BaselineError(f"Migration input {_display_path(path)} is not a 0.5 baseline.")
        containers = [container for container in _LEGACY_ROW_CONTAINERS if isinstance(payload.get(container), list)]
        # One container is the supported case; two would migrate differently in different ports, so the file is refused.
        if len(containers) > 1:
            raise BaselineError(
                f"Migration input {_display_path(path)} carries more than one row container "
                f"({', '.join(containers)}); a migration input must name exactly one."
            )
        # An empty review list is valid. A missing list gives the migration nothing it can verify.
        if not containers:
            raise BaselineError(f'Migration input {_display_path(path)} must carry a "findings" or "entries" list.')
        rows = payload[containers[0]]
        # Validate all saved reviews before writing any of them to the destination.
        for index, row in enumerate(rows):
            # A hand edit or merge can leave a null row. Report its location instead of dropping reviewed debt.
            if not isinstance(row, dict):
                raise BaselineError(f"Migration input {_display_path(path)}: {containers[0]}[{index}] must be a JSON object.")
        return tuple(rows)

    def _require_distinct_paths(self, input_path: Path, output_path: Path) -> None:
        """Refuse an output that is the input by spelling, resolved link target, or inode.

        Args:
            input_path: The 0.5 baseline as _absolute_path returned it (a relative selection joined under the project root, an absolute one
                unchanged), which the migration must leave intact; it is the path named in the error.
            output_path: Where the migrated baseline will be written, as _absolute_path returned it; the same-file check runs only when both files
                already exist.

        Returns:
            None. Verifies that the migration output is separate from the input.

        Raises:
            BaselineError: When both paths resolve to the same location, or both exist and are the same file on disk, as a hard link makes them.
        """
        if input_path.resolve() == output_path.resolve():
            raise BaselineError(f"Migration output must be a different file from its input: {input_path}")
        # Two existing paths can resolve to different names and still refer to the same file through a hard link.
        if output_path.exists() and input_path.exists() and os.path.samefile(input_path, output_path):
            raise BaselineError(f"Migration output must be a different file from its input: {input_path}")

    def _decode(self, path: str | Path) -> dict[str, Any]:
        """Read one baseline file into a JSON object, turning every file failure into a reason the user can act on.

        Args:
            path: Baseline the user selected, relative to the project root or absolute; it is named, with forward slashes, in the not-found,
                unreadable and encoding errors.

        Returns:
            The decoded JSON root object; its schemaVersion, toolLanguage and rows are not yet checked.

        Raises:
            BaselineError: When the path is not an existing regular file, cannot be read, is not valid UTF-8, is not valid JSON, or has a root that is
                not a JSON object.
        """
        display_path = _display_path(path)
        absolute_path = self._absolute_path(path)
        # A missing file cannot hide debt, so the user gets an error instead of a run that looks clean.
        if not absolute_path.is_file():
            raise BaselineError(f"Baseline file not found: {display_path}")
        try:
            payload = json.loads(absolute_path.read_text(encoding="utf-8"))
        # For example, permissions can change after a user selects a file with --baseline.
        except OSError as exc:
            raise BaselineError(f"Unable to read baseline file: {display_path}") from exc
        # For example, an editor may have saved the selected baseline in a non-UTF-8 encoding.
        except UnicodeDecodeError as exc:
            raise BaselineError(f"Baseline file is not valid UTF-8: {display_path}") from exc
        # For example, a hand-edited baseline may have a trailing comma or an unfinished object.
        except json.JSONDecodeError as exc:
            raise BaselineError(f"Invalid baseline JSON: {exc.msg}") from exc
        if not isinstance(payload, dict):
            raise BaselineError("Baseline root must be a JSON object.")
        return payload

    def _absolute_path(self, path: str | Path) -> Path:
        """Resolve a selected baseline path against this analysis project.

        Args:
            path: Baseline location the user selected; an absolute path is kept even when it points outside the project, and a relative one is
                anchored to the project root.

        Returns:
            The absolute selection unchanged, or the relative selection joined under the store's project root; symlinks and .. segments are not
            resolved.
        """
        candidate = Path(path)
        # An absolute selection already identifies the user's file, inside the project or outside it.
        if candidate.is_absolute():
            return candidate
        return self._project_root / candidate


def generate_baseline(
    *,
    project_root: str | Path,
    path: str | Path,
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None = None,
) -> BaselineReport:
    """Persist the current findings as the user's accepted debt.

    The report counts written entries and sensitive findings separately, with zero baseline suppressions. Other report filters still apply.

    Args:
        project_root: Project root that anchors a relative destination and determines its display path.
        path: Destination baseline file, relative or absolute.
        findings: Findings to record as the new baseline.
        declaration_position: Declaration resolver from the runner; ``None`` ranks by line.

    Returns:
        Report describing the just-written baseline.
    """
    data = BaselineStore(project_root).write(path, findings, declaration_position)
    return BaselineReport(
        path=data.path,
        generated=True,
        total_entries=len(data.entries),
        suppressed_findings=0,
        stale_evaluation="generated",
        source=_baseline_source(path),
        sensitive_counted=data.sensitive_total(),
    )


def migrate_baseline(
    *,
    project_root: str | Path,
    input_path: str | Path,
    output_path: str | Path,
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None = None,
) -> BaselineReport:
    """Carry reviews from a 0.5 baseline into a new file when they still match this scan.

    Args:
        project_root: Project root that anchors relative input and output paths and determines the report's display path.
        input_path: The 0.5 baseline to read; it is left byte-identical.
        output_path: Destination for the migrated baseline. It must name a different file from input_path.
        findings: This run's findings, from which the new identities are computed.
        declaration_position: Declaration resolver from the runner; ``None`` ranks by line.

    Returns:
        Report with the written entry and sensitive finding counts. Both are zero when no legacy review matches.
    """
    migration = BaselineStore(project_root).migrate(input_path, output_path, findings, declaration_position)
    return BaselineReport(
        path=migration.written_baseline.path,
        generated=True,
        total_entries=len(migration.written_baseline.entries),
        suppressed_findings=0,
        stale_evaluation="migrated",
        source=_baseline_source(output_path),
        sensitive_counted=migration.sensitive_counted,
    )


def apply_baseline(
    *,
    project_root: str | Path,
    path: str | Path,
    findings: Sequence[Finding],
    source: str,
    scan_scope: str = "full-project",
    declaration_position: Callable[[Finding], int] | None = None,
) -> BaselineApplyResult:
    """Spend reviewed counts and keep the findings that still need attention.
    Same-named declarations use their positions to keep separate reviews apart. A partial scan leaves unseen debt unresolved.

    Args:
        project_root: Project root used to locate a relative baseline and display its path.
        path: Baseline file to read, either absolute or relative to project_root.
        findings: Live findings to classify.
        source: Origin label recorded on the report (``explicit``/``default``).
        scan_scope: ``full-project`` when the run covered the whole project, ``partial-scope`` when paths narrowed it.
        declaration_position: Declaration resolver from the runner; ``None`` ranks by line.

    Returns:
        The retained findings, the report, all collisions and each finding's baseline classification.

    Raises:
        BaselineError: When the baseline cannot be read or validated, was written by another port, or constructing a finding identity fails.
    """
    baseline = BaselineStore(project_root).read(path)
    # Reviews are port-specific, so reject a foreign baseline before using its rows to classify findings.
    if baseline.tool_language != TOOL_LANGUAGE:
        raise BaselineError(
            f"Baseline {baseline.path} was written by {baseline.tool_language} and this run is {TOOL_LANGUAGE}; "
            "baselines are not shared across languages."
        )

    identities = _identities_or_error(findings, declaration_position)
    groups = _group_by_identity(findings, identities)
    statuses = _classify(findings, identities, groups, baseline.by_identity())
    retained_findings, counts = _partition(findings, statuses)
    # A partial scan can miss findings outside its scope, so only a full scan counts unmatched reviews as resolved.
    resolved_entries, resolved_occurrences = _resolved_surplus(baseline, groups, statuses) if scan_scope == "full-project" else ((), 0)

    return BaselineApplyResult(
        findings=retained_findings,
        report=BaselineReport(
            path=baseline.path,
            generated=False,
            total_entries=len(baseline.entries),
            suppressed_findings=counts["unchanged"],
            stale_evaluation=scan_scope,
            stale_entries=resolved_entries,
            source=source,
            new_count=counts["new"],
            unchanged_count=counts["unchanged"],
            absent_count=resolved_occurrences,
            collision_count=counts["collision"],
            not_eligible_count=counts["notEligible"],
        ),
        collisions=_collisions(groups),
        statuses={id(finding): status for finding, status in zip(findings, statuses, strict=True)},
    )


def require_overwritable_default_path(project_root: str | Path, path: str | Path, force: bool) -> None:
    """Check whether generation can replace a file at the conventional baseline name.
    An existing file must be a readable baseline for this port unless the user explicitly supplies `--force`.

    Args:
        project_root: Base directory used when the destination path is relative.
        path: Destination the user asked to generate.
        force: Whether to skip the overwrite check at the user's request.

    Returns:
        None. Checks the existing destination before the caller writes a baseline.

    Raises:
        BaselineError: When the existing file at the conventional path cannot be read as this port's baseline.
    """
    # The caller can bypass overwrite protection by forcing the write or choosing a different filename.
    if force or Path(path).name != DEFAULT_BASELINE_FILENAME:
        return
    absolute_path = Path(path) if Path(path).is_absolute() else Path(project_root) / path
    # Nothing there to protect, which is the ordinary first-generate case.
    if not absolute_path.exists() and not absolute_path.is_symlink():
        return
    try:
        existing = BaselineStore(project_root).read(path)
        # A baseline from another port can be readable but may still contain reviews the caller needs to keep.
        if existing.tool_language != TOOL_LANGUAGE:
            raise BaselineError(f"Baseline was written by {existing.tool_language}; this run is {TOOL_LANGUAGE}.")
    except BaselineError as exc:
        # A truncated default file, for example, is kept for recovery and the diagnostic explains the explicit override.
        raise BaselineError(f"Refusing to overwrite {_display_path(path)} without --force to preserve the retreat path. {exc}") from exc


def default_baseline_path(project_root: str | Path) -> Path:
    """Locate the conventional baseline for the project a user is analysing.

    Args:
        project_root: Project root that anchors the default baseline filename.

    Returns:
        Path to gruff-baseline.json beneath project_root; it is absolute only when project_root is absolute.
    """
    return Path(project_root) / DEFAULT_BASELINE_FILENAME


@dataclass(slots=True)
class _IdentityGroup:
    """Collect the occurrences that share one baseline identity.

    The matcher spends reviewed counts within a declaration.
    If the identity covers different declarations, the report keeps their findings visible.
    """

    indexes: list[int]
    declarations: set[str]
    subjects: list[str]
    rule_id: str
    path: str


def _identities_or_error(
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None,
) -> tuple[FindingIdentity | None, ...]:
    """Name eligible findings and translate identity failures into baseline errors.

    Args:
        findings: Scan occurrences whose identities will be stored or matched against reviewed debt.
        declaration_position: Declaration resolver used for occurrence identity, or None for line-based fallback.

    Returns:
        One identity per finding, with None for occurrences excluded from identity matching.

    Raises:
        BaselineError: An identity cannot be constructed, preserving the underlying diagnostic.
    """
    try:
        return finding_identities(findings, declaration_position)
    # For example, a symbol-less finding whose message is empty has nothing left to be named by.
    except BaselineIdentityError as exc:
        raise BaselineError(str(exc)) from exc


def _group_by_identity(findings: Sequence[Finding], identities: Sequence[FindingIdentity | None]) -> dict[str, _IdentityGroup]:
    """Collect the occurrences and declarations needed to apply one reviewed identity together.

    Args:
        findings: Scan occurrences in the order used to classify and report them.
        identities: Matching identity slots in the same order; None slots are omitted from groups.

    Returns:
        Groups keyed by identity, retaining occurrence indexes and distinct declarations and subjects.
    """
    groups: dict[str, _IdentityGroup] = {}
    for index, finding in enumerate(findings):
        named = identities[index]
        # Skip findings without identities so reviewed rows cannot suppress secrets or findings with the ordinal separator in their symbols.
        if named is None:
            continue
        group = groups.setdefault(
            named.identity,
            _IdentityGroup(indexes=[], declarations=set(), subjects=[], rule_id=finding.rule_id, path=finding.file_path),
        )
        group.indexes.append(index)
        group.declarations.add(named.declaration_key)
        if named.subject not in group.subjects:
            group.subjects.append(named.subject)
    return groups


def _classify(
    findings: Sequence[Finding],
    identities: Sequence[FindingIdentity | None],
    groups: dict[str, _IdentityGroup],
    reviewed_by_identity: dict[str, BaselineEntry],
) -> list[str]:
    """Classify reviewed debt without hiding collisions or ineligible findings.

    Args:
        findings: Scan occurrences whose positions determine which reviewed counts are spent first.
        identities: Identity slots aligned with findings; None marks an occurrence not eligible for matching.
        groups: Occurrences and declarations collected for each eligible identity.
        reviewed_by_identity: Accepted baseline rows that supply each identity's reviewed count.

    Returns:
        One status per finding in scan order: new, unchanged, collision, or notEligible.
    """
    statuses = ["new"] * len(findings)
    for index, named in enumerate(identities):
        # A finding with no identity is labelled before any lookup: a sensitive one, so no reviewed row can reach a
        # secret, or one whose symbol carries the ordinal separator and so cannot be named unambiguously.
        if named is None:
            statuses[index] = "notEligible"

    for identity, group in groups.items():
        # One identity over two declarations cannot separate them, so neither is hidden and the run says so by name.
        if len(group.declarations) > 1:
            for index in group.indexes:
                statuses[index] = "collision"
            continue
        reviewed = reviewed_by_identity.get(identity)
        reviewed_count = reviewed.count if reviewed is not None else 0
        # Spend the reviewed count on the earliest locations first, with unlocated findings sorted last. Ties keep scan order.
        for position, index in enumerate(sorted(group.indexes, key=lambda item: _spend_order(findings[item]))):
            statuses[index] = "unchanged" if position < reviewed_count else "new"
    return statuses


def _spend_order(finding: Finding) -> tuple[int, int]:
    """Order one identity's occurrences by line then column; an unlocated finding sorts last.

    Args:
        finding: Occurrence whose position decides which reviewed count is spent first.

    Returns:
        Line and column sorting key, using zero for an absent column.
    """
    line = finding.line if finding.line is not None else _UNLOCATED_SPEND_LINE
    return (line, finding.column if finding.column is not None else 0)


def _partition(findings: Sequence[Finding], statuses: Sequence[str]) -> tuple[list[Finding], dict[str, int]]:
    """Keep findings that still affect the gate and count every baseline status.

    Args:
        findings: Scan occurrences in their original reporting order.
        statuses: One classification per occurrence, in the same order as findings.

    Returns:
        Findings other than unchanged occurrences, preserving order, and counts by status.
    """
    gated: list[Finding] = []
    counts = {"new": 0, "unchanged": 0, "collision": 0, "notEligible": 0}
    for finding, status in zip(findings, statuses, strict=True):
        counts[status] += 1
        # Only unchanged findings leave the gated set; collisions and sensitive findings remain for severity-threshold evaluation.
        if status != "unchanged":
            gated.append(finding)
    return gated, counts


def _resolved_surplus(
    baseline: BaselineData,
    groups: dict[str, _IdentityGroup],
    statuses: Sequence[str],
) -> tuple[tuple[BaselineEntry, ...], int]:
    """Count reviewed occurrences that disappeared, leaving collided identities unresolved.

    Args:
        baseline: Reviewed rows against which the full scan's remaining debt is compared.
        groups: Live occurrences grouped by identity; an absent group means no occurrences remain.
        statuses: Classifications indexed by each group's occurrence indexes, used to skip collisions.

    Returns:
        Baseline rows carrying their resolved surplus counts, and the total resolved occurrences.
    """
    resolved: list[BaselineEntry] = []
    occurrences = 0
    for entry in baseline.entries:
        group = groups.get(entry.identity)
        # A collided identity is already accounted for by its collision; counting it resolved would double-report it.
        if group is not None and statuses[group.indexes[0]] == "collision":
            continue
        surplus = entry.count - (len(group.indexes) if group is not None else 0)
        if surplus <= 0:
            continue
        resolved.append(BaselineEntry(entry.identity, surplus, entry.rule_id, entry.path, entry.subject))
        occurrences += surplus
    return tuple(resolved), occurrences


def _collisions(groups: dict[str, _IdentityGroup]) -> tuple[BaselineCollision, ...]:
    """List identities shared by multiple declarations so the run can explain each collision.

    Args:
        groups: Occurrences grouped by the identity used to match reviewed baseline rows.

    Returns:
        Collision records with the rule, path and subjects from each ambiguous group.
    """
    return tuple(
        BaselineCollision(identity=identity, rule_id=group.rule_id, path=group.path, subjects=tuple(group.subjects))
        for identity, group in groups.items()
        if len(group.declarations) > 1
    )


def _document_from_findings(
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None,
) -> BaselineData:
    """Build counted baseline rows while recording sensitive occurrences only as per-rule totals.

    Args:
        findings: Current scan occurrences from which the accepted-debt document is generated.
        declaration_position: Declaration resolver for occurrence identity, or None for line-based fallback.

    Returns:
        Baseline data with identity-sorted rows, sensitive counts, and no assigned output path.
    """
    identities = _identities_or_error(findings, declaration_position)
    rows: dict[str, BaselineEntry] = {}
    sensitive_by_rule: dict[str, int] = {}

    for finding, named in zip(findings, identities, strict=True):
        # A sensitive finding is counted by rule and stored nowhere, so no row can ever hide a secret. A finding whose
        # symbol carries the ordinal separator has no identity either, but it is not a secret and is not counted as one.
        if named is None:
            if not is_baseline_eligible(finding):
                sensitive_by_rule[finding.rule_id] = sensitive_by_rule.get(finding.rule_id, 0) + 1
            continue
        previous = rows.get(named.identity)
        count = 1 if previous is None else previous.count + 1
        rows[named.identity] = BaselineEntry(
            identity=named.identity,
            count=count,
            rule_id=finding.rule_id,
            path=finding.file_path,
            subject=named.subject,
        )

    entries = tuple(row for _, row in sorted(rows.items()))
    return BaselineData(path="", tool_language=TOOL_LANGUAGE, entries=entries, sensitive_by_rule=sensitive_by_rule)


def _document_payload(data: BaselineData) -> dict[str, Any]:
    """Render baseline rows and sensitive counts without storing sensitive finding details.

    Args:
        data: Reviewed occurrences and per-rule sensitive counts to persist.

    Returns:
        Versioned JSON-ready document with a fresh generation timestamp.
    """
    return {
        "schemaVersion": BASELINE_SCHEMA_VERSION,
        "toolLanguage": data.tool_language,
        "generatedAt": datetime.now(UTC).isoformat(),
        "occurrences": [entry.to_dict() for entry in data.entries],
        "sensitive": {
            "eligible": False,
            "reason": _SENSITIVE_INELIGIBILITY_REASON,
            "counts": {"total": data.sensitive_total(), "byRule": dict(sorted(data.sensitive_by_rule.items()))},
        },
    }


def _accepted_by_legacy(rows: tuple[dict[str, Any], ...], findings: Sequence[Finding]) -> list[Finding]:
    """Match current findings to prior reviews before writing a migrated baseline.
    Exact fingerprints take priority. A remaining symbol-less review may match a message whose measured numbers changed.

    Args:
        rows: Legacy baseline rows, each able to review at most one current occurrence.
        findings: This run's findings, the only candidates a 0.5 row can accept.

    Returns:
        Accepted findings, using location order within exact and fallback matches.
    """
    exact_matches, remaining_rows, unmatched_findings = _exact_legacy_matches(rows, sorted(findings, key=_spend_order))
    reviews_by_key: dict[tuple[str | None, str | None, str | None, str | None], int] = {}
    # Each unspent row grants one review to a later match if its old fingerprint no longer applies.
    for row in remaining_rows:
        symbol = _row_text(row, "symbol")
        message = _row_text(row, "message")
        # A file-level measurement can grow while describing the same reviewed problem.
        if symbol is None and message is not None:
            message = normalise_measured_values(message)
        key = (_row_text(row, "ruleId"), _row_text(row, "file") or _row_text(row, "filePath"), symbol, message)
        reviews_by_key[key] = reviews_by_key.get(key, 0) + 1

    accepted = exact_matches
    # Try the remaining findings in location order to spend each review predictably.
    for finding in unmatched_findings:
        rule_id, path, symbol, message = finding.rule_id, finding.file_path, finding.symbol, finding.message
        # A legacy entry may omit a message or symbol, so try the most specific recorded description first.
        for candidate_key in (
            (rule_id, path, symbol, message),
            (rule_id, path, symbol, None),
            (rule_id, path, None, normalise_measured_values(message)),
            (rule_id, path, None, None),
        ):
            # Once a stored review is spent, later occurrences stay visible unless another review covers them.
            if reviews_by_key.get(candidate_key, 0) > 0:
                reviews_by_key[candidate_key] -= 1
                accepted.append(finding)
                break
    return accepted


def _exact_legacy_matches(rows: tuple[dict[str, Any], ...], findings: list[Finding]) -> tuple[list[Finding], list[dict[str, Any]], list[Finding]]:
    """Spend exact legacy reviews before a weaker match can claim them.
    Use the returned unspent rows and findings for fallback matching, so a description change does not claim the same review twice.

    Args:
        rows: Legacy reviews with optional fingerprint fields.
        findings: Current occurrences in location order.

    Returns:
        Exact matches, unspent rows and unmatched findings.
    """
    by_fingerprint: dict[tuple[str | None, str | None, str], list[int]] = {}
    # Older row shapes may lack a fingerprint and are handled by the fallback matcher.
    for index, row in enumerate(rows):
        fingerprint = _row_text(row, "fingerprint")
        # A present fingerprint identifies the review within the same rule and file.
        if fingerprint is not None:
            key = (_row_text(row, "ruleId"), _row_text(row, "file") or _row_text(row, "filePath"), fingerprint)
            by_fingerprint.setdefault(key, []).append(index)

    accepted: list[Finding] = []
    pending: list[Finding] = []
    spent: set[int] = set()
    # Match unchanged findings first so a weaker match cannot use their reviews.
    for finding in findings:
        matches = by_fingerprint.get((finding.rule_id, finding.file_path, finding.fingerprint()))
        # Spending one row leaves other occurrences available for separate review.
        if matches:
            spent.add(matches.pop())
            accepted.append(finding)
        else:
            pending.append(finding)
    return accepted, [row for index, row in enumerate(rows) if index not in spent], pending


def _row_text(row: dict[str, Any], key: str) -> str | None:
    """Read a legacy baseline field as nonempty text.

    Args:
        row: Stored 0.5 baseline occurrence whose optional fields limit matching.
        key: Matching field to read from that occurrence.

    Returns:
        Nonempty field text, or None if the field is absent, empty, or not a string. None for a symbol or message removes that matching constraint.
        A row without a rule ID or a usable path cannot match.
    """
    value = row.get(key)
    return value if isinstance(value, str) and value else None


def _entries_from_payload(payload: dict[str, Any]) -> tuple[BaselineEntry, ...]:
    """Read the rows that determine which reviewed findings may stay hidden.
    The baseline reader calls this after checking its version and refuses duplicate identities whose counts cannot both apply.

    Args:
        payload: Decoded v3 baseline root whose schemaVersion has already been checked; only its occurrences list is read here.

    Returns:
        One validated row per occurrence, in file order; empty when the file accepted nothing.

    Raises:
        BaselineError: When occurrences is missing or invalid, a row fails validation, or an identity repeats.
    """
    rows = payload.get("occurrences")
    # Without a list of occurrences there is no deterministic set of reviewed findings to apply.
    if not isinstance(rows, list):
        raise BaselineError('Baseline key "occurrences" must be a list.')
    entries: list[BaselineEntry] = []
    identities: set[str] = set()
    # Restore all reviewed counts in file order before any finding can be suppressed.
    for index, row in enumerate(rows):
        # Reject the baseline if a non-object row cannot supply the identity and count needed for matching.
        if not isinstance(row, dict):
            raise BaselineError(f"Baseline occurrences[{index}] must be a JSON object.")
        entry = BaselineEntry.from_dict(row, index)
        # A merge can duplicate a row. Reject it so neither count silently overrides the other.
        if entry.identity in identities:
            raise BaselineError(f'Baseline occurrences[{index}] repeats identity "{entry.identity}".')
        identities.add(entry.identity)
        entries.append(entry)
    return tuple(entries)


def _sensitive_counts_from_payload(payload: dict[str, Any]) -> dict[str, int]:
    """Read the per-rule sensitive counts a baseline recorded without storing the findings themselves.

    Args:
        payload: Decoded v3 baseline root; the counts are read from sensitive.counts.byRule.

    Returns:
        Sensitive counts keyed by rule id as text, keeping only integer values and dropping booleans; empty when the sensitive, counts or byRule
        object is absent or malformed.
    """
    sensitive = payload.get("sensitive")
    if not isinstance(sensitive, dict):
        return {}
    counts = sensitive.get("counts")
    if not isinstance(counts, dict):
        return {}
    by_rule = counts.get("byRule")
    if not isinstance(by_rule, dict):
        return {}
    return {str(rule): value for rule, value in by_rule.items() if isinstance(value, int) and not isinstance(value, bool)}


def _optional_text(row: dict[str, Any], key: str) -> str:
    """Restore optional baseline descriptions while tolerating absent or non-text values.

    Args:
        row: Stored baseline occurrence containing optional descriptive fields.
        key: Description field to restore.

    Returns:
        Stored string, or an empty string when no string was recorded.
    """
    value = row.get(key)
    return value if isinstance(value, str) else ""


def _read_bytes(path: Path, display_path: str) -> bytes:
    """Read a baseline whole so migration can check that its input survives byte for byte.

    Args:
        path: Resolved baseline file to read from disk.
        display_path: User-facing path to name when the read fails.

    Returns:
        Complete baseline file contents without decoding or normalization.

    Raises:
        BaselineError: The baseline cannot be read, with the display path in the error.
    """
    try:
        return path.read_bytes()
    # For example, the user may pass a --migrate-baseline path that was deleted between runs.
    except OSError as exc:
        raise BaselineError(f"Unable to read baseline file: {display_path}") from exc


def _atomic_write_text(path: Path, text: str) -> None:
    """Replace a baseline only after its complete JSON text reaches disk, so an interrupted write keeps the old file.

    Args:
        path: Final baseline destination; its parent directory must already exist, because the staging file is created there so the replace stays on
            one filesystem.
        text: The complete serialised baseline, written as UTF-8 before it replaces the destination.

    Returns:
        None. Writes and syncs the staged text, then replaces the destination.

    Raises:
        Exception: Any failure while writing, syncing or replacing the staging file, typically an OSError such as a full disk, is re-raised unchanged
            after an attempt to remove the staging file, leaving the destination as it was.
    """
    handle_id, staging_path = tempfile.mkstemp(prefix="gruff-baseline-", dir=str(path.parent), text=True)
    try:
        with os.fdopen(handle_id, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging_path, path)
    # A full disk can interrupt staging, so try to remove the temporary file and leave the destination intact.
    except Exception:
        # A cleanup failure must not hide the write error the user needs to act on.
        with suppress(OSError):
            os.unlink(staging_path)
        raise


def _display_path(path: str | Path) -> str:
    """Render a baseline path consistently in reports and diagnostics.

    Args:
        path: Baseline path as the user gave it, or the project-relative or absolute form that _report_path chose to show.

    Returns:
        Path text using forward slashes on both Windows and POSIX, with no relativisation or resolution.
    """
    return str(path).replace("\\", "/")


def _report_path(project_root: Path, requested: str | Path, absolute_path: Path) -> str:
    """Choose the baseline path label to show in analysis output.

    Args:
        project_root: Store's project root used to shorten absolute selections that share its path prefix.
        requested: Baseline path as the user selected it; a relative one is shown as given, with backslashes turned into forward slashes.
        absolute_path: The Path returned by _absolute_path, used only for absolute selections. It may lie outside the project root.

    Returns:
        Forward-slash display path. Relative selections retain their spelling apart from slash direction.
        An absolute selection is shown relative to the project root if it starts with that root's path components, or in full otherwise.
        The comparison does not resolve symlinks or parent-directory segments.
    """
    requested_path = Path(requested)
    # A user-entered relative path is already the project-oriented label they expect to see in the report.
    if not requested_path.is_absolute():
        return _display_path(requested)
    try:
        return _display_path(absolute_path.relative_to(project_root))
    # An absolute selection outside the project root prefix keeps its full path in the report.
    except ValueError:
        return _display_path(absolute_path)


def _baseline_source(path: str | Path) -> str:
    """Label a generated or migrated baseline default when its file name is the conventional gruff-baseline.json, and explicit for any other name.

    A bare --generate-baseline flag supplies gruff-baseline.json, which is the default case, but the label comes from the file name alone, so a
    destination the user typed in any directory is also reported as default when it is named gruff-baseline.json.

    Args:
        path: Destination of the generated or migrated baseline; only its final name is compared.

    Returns:
        default when the file name is gruff-baseline.json, otherwise explicit.
    """
    return "default" if Path(path).name == DEFAULT_BASELINE_FILENAME else "explicit"
