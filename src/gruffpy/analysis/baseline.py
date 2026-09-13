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
    """Carry the user's baseline choices into the analysis pipeline.

    Use after CLI or API options select generation, migration, application, or no baseline at all.

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
        """Rebuild one reviewed row, refusing anything that could expire on an edit or leak a finding's text.

        Args:
            row: Decoded occurrence object; a hand-edited file may carry anything at all.
            index: Zero-based position, named in the error so the user can find the row.

        Returns:
            Validated row ready to match against live findings.

        Raises:
            BaselineError: When the identity is not 16 hex characters, the count is below one, or a forbidden key is present.
        """
        identity = row.get("identity")
        # An identity that is not the ratified digest shape cannot have come from a generator, so the row is refused.
        if not isinstance(identity, str) or len(identity) != 16 or any(character not in "0123456789abcdef" for character in identity):
            raise BaselineError(f"Baseline occurrences[{index}].identity must be 16 lowercase hex characters.")

        count = row.get("count")
        # A count below one would mean a reviewed identity that suppresses nothing, which is a hand edit gone wrong.
        if not isinstance(count, int) or isinstance(count, bool) or count < 1:
            raise BaselineError(f"Baseline occurrences[{index}].count must be a positive integer.")

        # A positional or re-classifiable field is how a 0.5 baseline expired on every edit, so its presence fails the file.
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
            Every row keyed by its identity; empty when the baseline accepted nothing.
        """
        return {entry.identity: entry for entry in self.entries}

    def sensitive_total(self) -> int:
        """Count the sensitive findings this file recorded without storing.

        Returns:
            Total across every rule; zero when the scan found no secrets.
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
        not_eligible_count: Sensitive findings, which no row may hide.
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
    """Carry the findings a user must still act on back to the runner, with the accounting behind them.

    An empty findings list means every live finding was already reviewed, or the scan found none at all.

    Attributes:
        findings: The gated set: new, collided, and sensitive findings, in scan order.
        report: What moved, for the reporters.
        collisions: Identities that covered two declarations; each becomes a diagnostic the user reads.
    """

    findings: list[Finding]
    report: BaselineReport
    collisions: tuple[BaselineCollision, ...] = ()


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
        """Anchor baseline paths to the project being analysed."""
        self._project_root = Path(project_root)

    def read(self, path: str | Path) -> BaselineData:
        """Load the reviewed debt from the baseline the user selected.

        Args:
            path: Baseline location relative to the project root, or absolute.

        Returns:
            Parsed baseline ready to match against this run's findings.

        Raises:
            BaselineError: When the file is missing, unreadable, malformed, a 0.5 layout, or written by another port.
        """
        display_path = _display_path(path)
        payload = self._decode(path)

        schema = payload.get("schemaVersion")
        # A 0.5 file fails closed and names the command that carries its reviews forward, so nothing is silently dropped.
        if schema in LEGACY_BASELINE_SCHEMA_VERSIONS:
            raise BaselineError(
                f'Baseline schema "{schema}" is a 0.5 baseline. Migrate it to a separate file with '
                f"`gruff-py analyse --migrate-baseline {display_path} --generate-baseline <new path>`; the original is preserved."
            )
        # Any other schemaVersion is a pre-0.6 document, and every one of them takes the same route forward.
        if schema != BASELINE_SCHEMA_VERSION:
            raise BaselineError(
                f'Baseline schemaVersion must be "{BASELINE_SCHEMA_VERSION}"; carry an older file\'s reviews forward '
                f"with `gruff-py analyse --migrate-baseline {display_path} --generate-baseline <new path>`, "
                "which leaves the original untouched."
            )

        tool_language = payload.get("toolLanguage")
        # A baseline names its writer, so another port's file is refused instead of reporting every row resolved.
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
            findings: Findings to record; sensitive ones are counted by rule and never stored.
            declaration_position: Declaration resolver from the runner; ``None`` ranks by line, as a direct API call does.

        Returns:
            The file just written, including the sensitive counts it recorded rather than stored.

        Raises:
            BaselineError: When a finding cannot be named, or the file cannot be written.
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
            What was written and how much of the 0.5 file's review carried across.

        Raises:
            BaselineError: When the input is missing or not a 0.5 baseline, the two paths are one file, or the write fails.
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
        """Read the rows of a 0.5 baseline, the only shape a migration accepts as its input."""
        try:
            payload = json.loads(contents.decode("utf-8"))
        # For example, a hand-edited 0.5 baseline may carry a trailing comma the decoder rejects.
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BaselineError(f"Invalid baseline JSON: {_display_path(path)}") from exc
        if not isinstance(payload, dict) or payload.get("schemaVersion") not in LEGACY_BASELINE_SCHEMA_VERSIONS:
            raise BaselineError(f"Migration input {_display_path(path)} is not a 0.5 baseline.")
        containers = [container for container in _LEGACY_ROW_CONTAINERS if isinstance(payload.get(container), list)]
        # One container is the supported case; two would migrate differently in different ports, so the file is refused.
        if len(containers) > 1:
            raise BaselineError(
                f"Migration input {_display_path(path)} carries more than one row container "
                f"({', '.join(containers)}); a migration input must name exactly one."
            )
        if not containers:
            raise BaselineError(f'Migration input {_display_path(path)} must carry a "findings" or "entries" list.')
        rows = payload[containers[0]]
        return tuple(row for row in rows if isinstance(row, dict))

    def _require_distinct_paths(self, input_path: Path, output_path: Path) -> None:
        """Refuse an output that is the input by spelling, resolved link target, or inode."""
        if input_path.resolve() == output_path.resolve():
            raise BaselineError(f"Migration output must be a different file from its input: {input_path}")
        # A symlink or a hard link would make the "different" output the same bytes, destroying the retreat path.
        if output_path.exists() and input_path.exists() and os.path.samefile(input_path, output_path):
            raise BaselineError(f"Migration output must be a different file from its input: {input_path}")

    def _decode(self, path: str | Path) -> dict[str, Any]:
        """Read one baseline file into a JSON object, turning every file failure into a reason the user can act on."""
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
        """Resolve a selected baseline path against this analysis project."""
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

    Findings stay visible on the generating run; the report confirms what was written and what was only counted.

    Args:
        project_root: Resolved project root used for display paths.
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
    """Carry a 0.5 baseline's reviews into a new file and report what came across.

    Args:
        project_root: Resolved project root used for display paths.
        input_path: The 0.5 baseline to read; it is left byte-identical.
        output_path: Where the migrated baseline is written.
        findings: This run's findings, from which the new identities are computed.
        declaration_position: Declaration resolver from the runner; ``None`` ranks by line.

    Returns:
        Report describing the migrated baseline.
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
    """Separate the debt a user already reviewed from the findings they still need to act on.

    Each live finding is classified in this order: a sensitive finding is never eligible, an identity covering two
    declarations is a collision that hides nothing, occurrences within the reviewed count are unchanged, and the
    rest are new. Partial scans leave resolved debt unjudged, because an unmatched row may simply belong to a file
    this run never opened.

    Args:
        project_root: Resolved project root used for display paths.
        path: Baseline file to read.
        findings: Live findings to classify.
        source: Origin label recorded on the report (``explicit``/``default``).
        scan_scope: ``full-project`` when the run covered the whole project, ``partial-scope`` when paths narrowed it.
        declaration_position: Declaration resolver from the runner; ``None`` ranks by line.

    Returns:
        The gated findings, the report, and every collision the run must name.

    Raises:
        BaselineError: When the baseline cannot be read, or was written by another port.
    """
    baseline = BaselineStore(project_root).read(path)
    # A baseline written by another port would report every row resolved and invite a destructive regenerate.
    if baseline.tool_language != TOOL_LANGUAGE:
        raise BaselineError(
            f"Baseline {baseline.path} was written by {baseline.tool_language} and this run is {TOOL_LANGUAGE}; "
            "baselines are not shared across languages."
        )

    identities = _identities_or_error(findings, declaration_position)
    groups = _group_by_identity(findings, identities)
    statuses = _classify(findings, identities, groups, baseline.by_identity())
    gated, counts = _partition(findings, statuses)
    # Only a full scan proves reviewed debt was fixed; a narrowed run never opened the other files.
    resolved_entries, resolved_occurrences = _resolved_surplus(baseline, groups, statuses) if scan_scope == "full-project" else ((), 0)

    return BaselineApplyResult(
        findings=gated,
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
    )


def require_overwritable_default_path(project_root: str | Path, path: str | Path, force: bool) -> None:
    """Refuse to write a baseline over a 0.5 file at the shared default path.

    All five ports write and auto-discover the same filename, so without this an ordinary upgrade-then-generate
    destroys the 0.5 baseline that is the user's documented retreat path, before they know they need it.
    Regenerating v3 over v3 is not destructive, because v3 is what the tool now reads.

    Args:
        project_root: Resolved project root the destination is relative to.
        path: Destination the user asked to generate.
        force: True when the user passed ``--force`` and means to overwrite the older file.

    Raises:
        BaselineError: When the default path already holds a file this version would not read.
    """
    # Any other destination is the user's own choice of file, and any v3 file is what this version already reads.
    if force or Path(path).name != DEFAULT_BASELINE_FILENAME:
        return
    absolute_path = Path(path) if Path(path).is_absolute() else Path(project_root) / path
    # Nothing there to protect, which is the ordinary first-generate case.
    if not absolute_path.is_file():
        return
    try:
        existing = json.loads(absolute_path.read_text(encoding="utf-8"))
    # For example, a hand-edited or truncated file cannot be classified, so it is left alone rather than destroyed.
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    schema = existing.get("schemaVersion") if isinstance(existing, dict) else None
    if not isinstance(schema, str) or schema == BASELINE_SCHEMA_VERSION:
        return
    raise BaselineError(
        f'{_display_path(path)} is a "{schema}" baseline, not "{BASELINE_SCHEMA_VERSION}"; generating over it would destroy '
        f"the retreat path. Migrate it with `gruff-py analyse --migrate-baseline {_display_path(path)} "
        "--generate-baseline <new path>`, or pass --force to overwrite it."
    )


def default_baseline_path(project_root: str | Path) -> Path:
    """Locate the conventional baseline for the project a user is analysing.

    Args:
        project_root: Project root that anchors the default baseline filename.

    Returns:
        Absolute path to the conventional ``gruff-baseline.json`` location.
    """
    return Path(project_root) / DEFAULT_BASELINE_FILENAME


@dataclass(slots=True)
class _IdentityGroup:
    """Every occurrence of one identity in this run, plus what it takes to judge them together."""

    indexes: list[int]
    declarations: set[str]
    subjects: list[str]
    rule_id: str
    path: str


def _identities_or_error(
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None,
) -> tuple[FindingIdentity | None, ...]:
    """Name every eligible finding, reporting an unnameable one as a baseline failure rather than a traceback."""
    try:
        return finding_identities(findings, declaration_position)
    # For example, a rule emitting a symbol that already contains "#" cannot be given an unambiguous ordinal.
    except BaselineIdentityError as exc:
        raise BaselineError(str(exc)) from exc


def _group_by_identity(findings: Sequence[Finding], identities: Sequence[FindingIdentity | None]) -> dict[str, _IdentityGroup]:
    """Bucket every eligible finding by identity, remembering the declarations and subjects each one covers."""
    groups: dict[str, _IdentityGroup] = {}
    for index, finding in enumerate(findings):
        named = identities[index]
        # A sensitive finding has no identity, so it joins no group and no reviewed row can ever reach it.
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
    """Label every finding new, unchanged, collision, or notEligible, spending each reviewed count in file order."""
    statuses = ["new"] * len(findings)
    for index, named in enumerate(identities):
        # Sensitive findings are labelled before any lookup, so no reviewed row can reach a secret.
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
        # The reviewed count is spent lowest line first, so two ports hide the same occurrences and not merely the same number.
        for position, index in enumerate(sorted(group.indexes, key=lambda item: _spend_order(findings[item]))):
            statuses[index] = "unchanged" if position < reviewed_count else "new"
    return statuses


def _spend_order(finding: Finding) -> tuple[int, int]:
    """Order one identity's occurrences by line then column; an unlocated finding sorts last."""
    line = finding.line if finding.line is not None else _UNLOCATED_SPEND_LINE
    return (line, finding.column if finding.column is not None else 0)


def _partition(findings: Sequence[Finding], statuses: Sequence[str]) -> tuple[list[Finding], dict[str, int]]:
    """Split the findings into the hidden set and the gated set, in scan order, and count each status."""
    gated: list[Finding] = []
    counts = {"new": 0, "unchanged": 0, "collision": 0, "notEligible": 0}
    for finding, status in zip(findings, statuses, strict=True):
        counts[status] += 1
        # Only an unchanged finding leaves the gated set; a collision or a secret stays visible and still fails the run.
        if status != "unchanged":
            gated.append(finding)
    return gated, counts


def _resolved_surplus(
    baseline: BaselineData,
    groups: dict[str, _IdentityGroup],
    statuses: Sequence[str],
) -> tuple[tuple[BaselineEntry, ...], int]:
    """Find every reviewed identity with fewer live occurrences than reviewed, which is debt the user has since fixed."""
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
    """List the identities that covered two declarations, so the run can name each one for the user."""
    return tuple(
        BaselineCollision(identity=identity, rule_id=group.rule_id, path=group.path, subjects=tuple(group.subjects))
        for identity, group in groups.items()
        if len(group.declarations) > 1
    )


def _document_from_findings(
    findings: Sequence[Finding],
    declaration_position: Callable[[Finding], int] | None,
) -> BaselineData:
    """Build the rows and sensitive counts a generated baseline records, ordered so two identical runs write one file."""
    identities = _identities_or_error(findings, declaration_position)
    rows: dict[str, BaselineEntry] = {}
    sensitive_by_rule: dict[str, int] = {}

    for finding, named in zip(findings, identities, strict=True):
        # A sensitive finding is counted by rule and stored nowhere, so no row can ever hide a secret.
        if named is None:
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
    """Render one baseline document, including the sensitive block that explains what it deliberately did not store."""
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
    """Keep the current findings a 0.5 baseline had already accepted, matching only on fields that file actually stored.

    A 0.5 row is matched on its rule and path, narrowed by its symbol and message when it recorded them, and it
    accepts as many occurrences as the file held. A finding the old baseline never covered stays visible.
    """
    budget_by_key: dict[tuple[str | None, str | None, str | None, str | None], int] = {}
    for row in rows:
        key = (
            _row_text(row, "ruleId"),
            _row_text(row, "file") or _row_text(row, "filePath"),
            _row_text(row, "symbol"),
            _row_text(row, "message"),
        )
        budget_by_key[key] = budget_by_key.get(key, 0) + 1

    accepted: list[Finding] = []
    # Lowest line first, so a 0.5 row covering fewer occurrences than exist today accepts the same ones on every port.
    for finding in sorted(findings, key=_spend_order):
        rule_id, path, symbol, message = finding.rule_id, finding.file_path, finding.symbol, finding.message
        # Try the most specific row first, then the shapes a sparser 0.5 writer produced, so no accepted debt is lost.
        for candidate_key in (
            (rule_id, path, symbol, message),
            (rule_id, path, symbol, None),
            (rule_id, path, None, message),
            (rule_id, path, None, None),
        ):
            if budget_by_key.get(candidate_key, 0) > 0:
                budget_by_key[candidate_key] -= 1
                accepted.append(finding)
                break
    return accepted


def _row_text(row: dict[str, Any], key: str) -> str | None:
    """Read one stored 0.5 field, treating an absent or non-text value as a field that row never narrowed on."""
    value = row.get(key)
    return value if isinstance(value, str) and value else None


def _entries_from_payload(payload: dict[str, Any]) -> tuple[BaselineEntry, ...]:
    """Restore every reviewed row from a validated v3 document."""
    rows = payload.get("occurrences")
    # Without a list of occurrences there is no deterministic set of reviewed findings to apply.
    if not isinstance(rows, list):
        raise BaselineError('Baseline key "occurrences" must be a list.')
    entries: list[BaselineEntry] = []
    for index, row in enumerate(rows):
        # Each reviewed occurrence must be an object; anything else is a hand edit that cannot be matched.
        if not isinstance(row, dict):
            raise BaselineError(f"Baseline occurrences[{index}] must be a JSON object.")
        entries.append(BaselineEntry.from_dict(row, index))
    return tuple(entries)


def _sensitive_counts_from_payload(payload: dict[str, Any]) -> dict[str, int]:
    """Read the per-rule sensitive counts a baseline recorded without storing the findings themselves."""
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
    """Read one optional descriptive string from a stored row; an absent field reads as empty."""
    value = row.get(key)
    return value if isinstance(value, str) else ""


def _read_bytes(path: Path, display_path: str) -> bytes:
    """Read a file whole, so a migration can prove its input survived byte for byte."""
    try:
        return path.read_bytes()
    # For example, the user may pass a --migrate-baseline path that was deleted between runs.
    except OSError as exc:
        raise BaselineError(f"Unable to read baseline file: {display_path}") from exc


def _atomic_write_text(path: Path, text: str) -> None:
    """Replace a baseline only after its complete JSON text reaches disk, so an interrupted write keeps the old file."""
    handle_id, staging_path = tempfile.mkstemp(prefix="gruff-baseline-", dir=str(path.parent), text=True)
    try:
        with os.fdopen(handle_id, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(staging_path, path)
    # For example, a full disk can fail after staging; remove the partial file and keep the original intact.
    except Exception:
        # A cleanup failure must not hide the write error the user needs to act on.
        with suppress(OSError):
            os.unlink(staging_path)
        raise


def _display_path(path: str | Path) -> str:
    """Render a baseline path consistently in reports and diagnostics."""
    return str(path).replace("\\", "/")


def _report_path(project_root: Path, requested: str | Path, absolute_path: Path) -> str:
    """Choose the shortest stable baseline path to show in analysis output."""
    requested_path = Path(requested)
    # A user-entered relative path is already the project-oriented label they expect to see in the report.
    if not requested_path.is_absolute():
        return _display_path(requested)
    try:
        return _display_path(absolute_path.relative_to(project_root))
    # For example, an external baseline cannot be displayed relative to this project root.
    except ValueError:
        return _display_path(absolute_path)


def _baseline_source(path: str | Path) -> str:
    """Label whether the user selected a path or gruff found the conventional one."""
    return "default" if Path(path).name == DEFAULT_BASELINE_FILENAME else "explicit"
