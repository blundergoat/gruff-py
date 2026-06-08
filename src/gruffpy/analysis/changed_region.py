"""Changed-region parsing and symbol-aware finding filtering."""

from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.source.source_file import SourceFile


@dataclass(frozen=True, slots=True)
class LineRange:
    """Inclusive one-based line range from a changed hunk."""

    start: int
    end: int

    def has_overlap(self, start: int, end: int) -> bool:
        """Return whether this range intersects ``start``-``end``.

        Args:
            start: First one-based line in the compared range.
            end: Last one-based line in the compared range.

        Returns:
            True when the ranges share at least one line.
        """
        return self.start <= end and start <= self.end


@dataclass(frozen=True, slots=True)
class ChangedRegionSet:
    """Resolved changed files, changed line ranges, and whole-file scopes.

    Attributes:
        source: Human-readable source for the changed-region data.
        ranges_by_file: Changed hunks keyed by project-relative display path.
        whole_files: Paths treated as entirely changed, such as untracked files.
    """

    source: str
    ranges_by_file: dict[str, tuple[LineRange, ...]] = field(default_factory=dict)
    whole_files: frozenset[str] = frozenset()

    @property
    def active(self) -> bool:
        """Return whether changed-region filtering was requested.

        Returns:
            True when the set should constrain analysis output.
        """
        return self.source != ""

    @property
    def changed_files(self) -> tuple[str, ...]:
        """Return deterministic changed file paths.

        Returns:
            Sorted display paths from hunk and whole-file scopes.
        """
        return tuple(sorted(set(self.ranges_by_file) | set(self.whole_files)))

    def is_file_changed(self, file_path: str) -> bool:
        """Return whether ``file_path`` is part of the changed scope.

        Args:
            file_path: Project-relative display path to test.

        Returns:
            True when the file has changed hunks or is whole-file changed.
        """
        key = _normalise_path(file_path)
        return key in self.whole_files or key in self.ranges_by_file

    def has_changed_range(self, file_path: str, start: int, end: int) -> bool:
        """Return whether any changed hunk overlaps ``file_path:start-end``.

        Args:
            file_path: Project-relative display path to test.
            start: First one-based line in the compared range.
            end: Last one-based line in the compared range.

        Returns:
            True when the file is whole-file changed or a hunk overlaps the range.
        """
        key = _normalise_path(file_path)
        if key in self.whole_files:
            return True
        return any(
            line_range.has_overlap(start, end) for line_range in self.ranges_by_file.get(key, ())
        )


@dataclass(frozen=True, slots=True)
class ChangedRegionFilterResult:
    """Finding filter result and out-of-scope count."""

    findings: list[Finding]
    suppressed_count: int


@dataclass(frozen=True, slots=True)
class _DeclarationRange:
    """Smallest symbol-like AST range used for symbol-scope filtering."""

    start: int
    end: int
    symbol: str | None


@dataclass(slots=True)
class _PatchState:
    """Current file header state while reading a unified diff."""

    current_path: str | None = None
    old_path: str | None = None
    new_file: bool = False


_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")

# These findings describe file/class-level or aggregate properties. Their
# reported spans are useful for full scans and hunk scope, but symbol scope
# should attribute them to the finding anchor so inherited debt does not survive
# every body edit.
_SYMBOL_SCOPE_ANCHOR_ONLY_RULE_IDS = frozenset(
    {
        "docs.dataclass-attributes",
        "docs.missing-module-docstring",
        "docs.todo-density",
        "naming.module-name-mismatch",
        "naming.test-naming-consistency",
        "size.attribute-count",
        "size.average-function-length",
        "size.class-length",
        "size.file-length",
        "size.public-method-count",
        "test-quality.naming-consistency",
    }
)


def parse_explicit_ranges(source_paths: tuple[str, ...], raw_ranges: str) -> ChangedRegionSet:
    """Build a changed-region set from ``1-3,8`` style ranges.

    Args:
        source_paths: Display paths the explicit ranges apply to.
        raw_ranges: Comma-separated one-based line ranges.

    Returns:
        Changed-region set covering the supplied paths and ranges.

    Raises:
        ValueError: Raised when the range syntax is invalid.
    """
    ranges = _parse_range_list(raw_ranges)
    return ChangedRegionSet(
        source="explicit",
        ranges_by_file={_normalise_path(path): ranges for path in source_paths},
    )


def parse_unified_diff(source: str, patch: str | bytes) -> ChangedRegionSet:
    """Parse unified diff text into new-side changed ranges.

    Args:
        source: Human-readable source label to record on the result.
        patch: Unified diff text or bytes.

    Returns:
        Changed-region set keyed by new-side file paths.
    """
    text = patch.decode("utf-8", errors="replace") if isinstance(patch, bytes) else patch
    ranges_by_file: dict[str, list[LineRange]] = {}
    whole_files: set[str] = set()
    changed_files: set[str] = set()
    state = _PatchState()

    for line in text.splitlines():
        if _did_consume_file_header(line, state, changed_files, whole_files):
            continue
        _consume_hunk_header(line, state, changed_files, whole_files, ranges_by_file)

    collapsed = {path: tuple(_merge_ranges(ranges)) for path, ranges in ranges_by_file.items()}
    for file_path in changed_files:
        collapsed.setdefault(file_path, ())
    return ChangedRegionSet(
        source=source,
        ranges_by_file=collapsed,
        whole_files=frozenset(whole_files),
    )


def _did_consume_file_header(
    line: str,
    state: _PatchState,
    changed_files: set[str],
    whole_files: set[str],
) -> bool:
    if line.startswith("diff --git "):
        _consume_diff_git_header(line, state)
        return True
    if line.startswith("new file mode"):
        state.new_file = True
        return True
    if line.startswith("--- "):
        _consume_old_file_header(line, state)
        return True
    if line.startswith("+++ "):
        _consume_new_file_header(line, state, changed_files, whole_files)
        return True
    return False


def _consume_diff_git_header(line: str, state: _PatchState) -> None:
    state.current_path = None
    state.old_path = None
    state.new_file = False
    parts = line.split()
    if len(parts) >= 4:
        state.old_path = _strip_diff_prefix(parts[2])
        state.current_path = _strip_diff_prefix(parts[3])


def _consume_old_file_header(line: str, state: _PatchState) -> None:
    state.old_path = _diff_header_path(line[4:])
    state.new_file = state.old_path is None


def _consume_new_file_header(
    line: str,
    state: _PatchState,
    changed_files: set[str],
    whole_files: set[str],
) -> None:
    parsed = _diff_header_path(line[4:])
    state.current_path = parsed or state.current_path
    if state.current_path is None:
        return
    changed_files.add(state.current_path)
    if state.new_file:
        whole_files.add(state.current_path)


def _consume_hunk_header(
    line: str,
    state: _PatchState,
    changed_files: set[str],
    whole_files: set[str],
    ranges_by_file: dict[str, list[LineRange]],
) -> None:
    match = _HUNK_RE.match(line)
    if match is None:
        return
    path = state.current_path or state.old_path
    if path is None:
        return
    changed_files.add(path)
    start = int(match.group(1))
    count = int(match.group(2) or "1")
    if path in whole_files:
        return
    if count > 0:
        ranges_by_file.setdefault(path, []).append(LineRange(start, start + count - 1))
    else:
        # Deletion-only hunks (``@@ -2 +1,0 @@``) carry no new-side lines; anchor a
        # zero-width range at the new-side position so symbol scope still surfaces
        # findings for the edited declaration instead of suppressing all of them.
        anchor = max(start, 1)
        ranges_by_file.setdefault(path, []).append(LineRange(anchor, anchor))


def changed_regions_from_git(
    project_root: Path,
    mode: str,
    paths: tuple[str, ...],
) -> ChangedRegionSet:
    """Resolve changed regions by invoking Git for the requested mode/ref.

    Args:
        project_root: Repository root used as Git's working directory.
        mode: ``working-tree``, ``staged``, ``unstaged``, or a base ref.
        paths: Optional pathspecs that limit Git's diff.

    Returns:
        Changed-region set parsed from Git output.

    Raises:
        ValueError: Raised when Git cannot resolve the diff.
    """
    if mode == "working-tree":
        changed = parse_unified_diff(
            "working-tree",
            _git(
                project_root,
                ["diff", "--unified=0", "--no-ext-diff", "--find-renames", "HEAD", "--", *paths],
            ),
        )
        untracked = _git_lines(
            project_root,
            ["ls-files", "--others", "--exclude-standard", "--", *paths],
        )
        return _with_whole_files(changed, untracked)
    if mode == "staged":
        return parse_unified_diff(
            "staged",
            _git(
                project_root,
                [
                    "diff",
                    "--cached",
                    "--unified=0",
                    "--no-ext-diff",
                    "--find-renames",
                    "--",
                    *paths,
                ],
            ),
        )
    if mode == "unstaged":
        return parse_unified_diff(
            "unstaged",
            _git(
                project_root,
                ["diff", "--unified=0", "--no-ext-diff", "--find-renames", "--", *paths],
            ),
        )
    return parse_unified_diff(
        mode,
        _git(
            project_root,
            [
                "diff",
                "--merge-base",
                "--unified=0",
                "--no-ext-diff",
                "--find-renames",
                mode,
                "--",
                *paths,
            ],
        ),
    )


def filter_sources_for_changed_regions(
    files: tuple[SourceFile, ...],
    changed: ChangedRegionSet,
) -> tuple[SourceFile, ...]:
    """Keep only discovered files present in the resolved changed file set.

    Args:
        files: Discovered source files before diff scoping.
        changed: Resolved changed-region data.

    Returns:
        Source files that should be parsed and analysed.
    """
    if not changed.active:
        return files
    return tuple(file for file in files if changed.is_file_changed(file.display_path))


def filter_findings_for_changed_regions(
    findings: list[Finding],
    units: list[AnalysisUnit],
    changed: ChangedRegionSet,
    scope: str,
) -> ChangedRegionFilterResult:
    """Filter findings to changed hunks or enclosing declarations.

    Args:
        findings: Findings produced by normal analysis.
        units: Parsed analysis units used to recover enclosing declarations.
        changed: Resolved changed-region data.
        scope: ``symbol`` for declaration-aware filtering or ``hunk`` for strict hunks.

    Returns:
        Retained findings and out-of-scope suppression count.
    """
    if not changed.active:
        return ChangedRegionFilterResult(findings=findings, suppressed_count=0)
    if scope == "hunk":
        return _filter_hunk_findings(findings, changed)

    declarations_by_file = {
        unit.file.display_path: _declaration_ranges(unit) for unit in units if unit.tree is not None
    }
    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if _is_finding_in_symbol_scope(
            finding,
            changed,
            declarations_by_file.get(finding.file_path, ()),
        ):
            kept.append(finding)
        else:
            suppressed += 1
    return ChangedRegionFilterResult(findings=kept, suppressed_count=suppressed)


def _filter_hunk_findings(
    findings: list[Finding],
    changed: ChangedRegionSet,
) -> ChangedRegionFilterResult:
    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if _is_finding_location_changed(finding, changed):
            kept.append(finding)
        else:
            suppressed += 1
    return ChangedRegionFilterResult(findings=kept, suppressed_count=suppressed)


def _is_finding_in_symbol_scope(
    finding: Finding,
    changed: ChangedRegionSet,
    declarations: tuple[_DeclarationRange, ...],
) -> bool:
    if finding.rule_id in _SYMBOL_SCOPE_ANCHOR_ONLY_RULE_IDS:
        return _is_finding_anchor_changed(finding, changed, declarations)
    if _is_finding_location_changed(finding, changed):
        return True
    if finding.line is None:
        return changed.is_file_changed(finding.file_path)
    declaration = _enclosing_declaration(finding, declarations)
    return declaration is not None and changed.has_changed_range(
        finding.file_path, declaration.start, declaration.end
    )


def _is_finding_anchor_changed(
    finding: Finding,
    changed: ChangedRegionSet,
    declarations: tuple[_DeclarationRange, ...],
) -> bool:
    if finding.line is None:
        return changed.is_file_changed(finding.file_path)
    anchor_end = _declaration_anchor_line(finding, declarations) or finding.line
    anchor_start = min(finding.line, anchor_end)
    anchor_end = max(finding.line, anchor_end)
    return changed.has_changed_range(finding.file_path, anchor_start, anchor_end)


def _declaration_anchor_line(
    finding: Finding,
    declarations: tuple[_DeclarationRange, ...],
) -> int | None:
    if finding.symbol is None or finding.end_line is None or finding.line is None:
        return None
    for declaration in declarations:
        if (
            _symbol_matches(finding.symbol, declaration.symbol)
            and finding.line <= declaration.start <= finding.end_line
        ):
            return declaration.start
    return None


def _is_finding_location_changed(finding: Finding, changed: ChangedRegionSet) -> bool:
    if finding.line is None:
        return changed.is_file_changed(finding.file_path)
    end_line = (
        finding.end_line
        if finding.end_line is not None and finding.end_line >= finding.line
        else finding.line
    )
    return changed.has_changed_range(finding.file_path, finding.line, end_line)


def _declaration_ranges(unit: AnalysisUnit) -> tuple[_DeclarationRange, ...]:
    assert unit.tree is not None
    declarations: list[_DeclarationRange] = []
    for node in ast.walk(unit.tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            end = getattr(node, "end_lineno", None) or node.lineno
            declarations.append(_DeclarationRange(node.lineno, end, _qualified_name(node)))
    return tuple(
        sorted(
            declarations,
            key=lambda declaration: (declaration.end - declaration.start, declaration.start),
        )
    )


def _qualified_name(node: ast.AST) -> str | None:
    name = getattr(node, "name", None)
    if not isinstance(name, str):
        return None
    parents = []
    current = getattr(node, "parent", None)
    while current is not None:
        parent_name = getattr(current, "name", None)
        if isinstance(parent_name, str) and isinstance(
            current, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef
        ):
            parents.append(parent_name)
        current = getattr(current, "parent", None)
    return ".".join([*reversed(parents), name])


def _enclosing_declaration(
    finding: Finding,
    declarations: tuple[_DeclarationRange, ...],
) -> _DeclarationRange | None:
    if finding.line is None:
        return None
    for declaration in declarations:
        if declaration.start <= finding.line <= declaration.end and _symbol_matches(
            finding.symbol, declaration.symbol
        ):
            return declaration
    for declaration in declarations:
        if declaration.start <= finding.line <= declaration.end:
            return declaration
    return None


def _symbol_matches(finding_symbol: str | None, declaration_symbol: str | None) -> bool:
    if finding_symbol is None or declaration_symbol is None:
        return True
    return finding_symbol == declaration_symbol or finding_symbol.endswith(f".{declaration_symbol}")


def _parse_range_list(raw_ranges: str) -> tuple[LineRange, ...]:
    ranges: list[LineRange] = []
    for chunk in raw_ranges.split(","):
        value = chunk.strip()
        if not value:
            continue
        if "-" in value:
            start_raw, end_raw = value.split("-", 1)
        else:
            start_raw = end_raw = value
        start = _parse_positive_line(start_raw, value)
        end = _parse_positive_line(end_raw, value)
        if end < start:
            raise ValueError(f"invalid changed range {value!r}: end must be >= start")
        ranges.append(LineRange(start, end))
    if not ranges:
        raise ValueError("--changed-ranges must include at least one line or range")
    return tuple(_merge_ranges(ranges))


def _parse_positive_line(raw_line: str, original: str) -> int:
    try:
        value = int(raw_line)
    except ValueError as exc:
        raise ValueError(
            f"invalid changed range {original!r}: line numbers must be integers"
        ) from exc
    if value < 1:
        raise ValueError(f"invalid changed range {original!r}: line numbers must be >= 1")
    return value


def _merge_ranges(ranges: list[LineRange] | tuple[LineRange, ...]) -> list[LineRange]:
    merged: list[LineRange] = []
    for current in sorted(ranges, key=lambda item: (item.start, item.end)):
        if not merged or current.start > merged[-1].end + 1:
            merged.append(current)
            continue
        previous = merged[-1]
        merged[-1] = LineRange(previous.start, max(previous.end, current.end))
    return merged


def _with_whole_files(changed: ChangedRegionSet, whole_paths: list[str]) -> ChangedRegionSet:
    whole = set(changed.whole_files)
    ranges_by_file = dict(changed.ranges_by_file)
    for path in whole_paths:
        normalised = _normalise_path(path)
        whole.add(normalised)
        ranges_by_file.setdefault(normalised, ())
    return ChangedRegionSet(
        source=changed.source,
        ranges_by_file=ranges_by_file,
        whole_files=frozenset(whole),
    )


def _git(project_root: Path, args: list[str]) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"unable to resolve git diff: {exc}") from exc
    return completed.stdout


def _git_lines(project_root: Path, args: list[str]) -> list[str]:
    output = _git(project_root, args)
    return [line for line in output.splitlines() if line]


def _diff_header_path(raw: str) -> str | None:
    value = raw.split("\t", 1)[0].strip()
    if value == "/dev/null":
        return None
    return _strip_diff_prefix(value)


def _strip_diff_prefix(path: str) -> str:
    # Decode Git's C-style quoting (``"b/caf\303\251.py"``) before testing the a/ b/
    # prefix. The quotes start the token, so a naive prefix check misses them and the
    # decoded display path keeps ``b/``, silently dropping the file in diff mode.
    decoded = _unquote_diff_path(path)
    if decoded.startswith("a/") or decoded.startswith("b/"):
        decoded = decoded[2:]
    return _normalise_path(decoded)


def _unquote_diff_path(value: str) -> str:
    """Decode a Git C-quoted path token, or return *value* unchanged when unquoted.

    Git wraps paths with non-ASCII bytes or control characters in double quotes and
    octal-escapes the offending bytes (``"b/caf\\303\\251.py"``). Plain paths - even
    those containing spaces - are emitted unquoted, so only quoted tokens are decoded.

    Args:
        value: Raw path token taken from a ``diff --git`` or ``+++``/``---`` header.

    Returns:
        The decoded UTF-8 path, matching the project-relative discovery display path.
    """
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        return value
    inner = value[1:-1]
    escapes = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}
    decoded = bytearray()
    index = 0
    while index < len(inner):
        char = inner[index]
        if char != "\\" or index + 1 >= len(inner):
            decoded.extend(char.encode("utf-8"))
            index += 1
            continue
        nxt = inner[index + 1]
        octal = inner[index + 1 : index + 4]
        if nxt in "0123" and len(octal) == 3 and all(digit in "01234567" for digit in octal):
            decoded.append(int(octal, 8))
            index += 4
        elif nxt in escapes:
            decoded.append(escapes[nxt])
            index += 2
        else:
            decoded.extend(nxt.encode("utf-8"))
            index += 2
    return decoded.decode("utf-8", errors="replace")


def _normalise_path(path: str) -> str:
    normalised = path.replace("\\", "/")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return normalised.strip("/")
