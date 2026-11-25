"""Choose the source files a scan can analyse under its project root.

Discovery applies the configured path rules, Git ignores and built-in exclusions.
The returned skip reasons and input errors explain which paths were left out.
"""

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from gruffpy.source.gitignore import GitignoreMatcher
from gruffpy.source.source_file import SourceFile, SourceFileType

PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py"})
TEXT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".conf",
        ".config",
        ".env",
        ".ini",
        ".json",
        ".toml",
        ".xml",
        ".yaml",
        ".yml",
    }
)

TEXT_FILENAMES: frozenset[str] = frozenset({"setup.cfg"})

VCS_IGNORED_DIRECTORIES: tuple[str, ...] = (".git", ".hg", ".svn")

FALLBACK_IGNORED_DIRECTORIES: tuple[str, ...] = (
    ".fleet",
    ".idea",
    ".mypy_cache",
    ".pyre",
    ".pytest_cache",
    ".pytype",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "htmlcov",
    "node_modules",
    "venv",
)

# Family contract section 7 skips third-party copies and `dist` even with a governing `.gitignore`.
#
# These names match at any depth and fold ASCII case.
# `build`, `coverage` and `htmlcov` remain fallback ignores.
THIRD_PARTY_DIRECTORIES: frozenset[str] = frozenset({"bower_components", "dist", "third-party", "third_party", "vendor", "vendors"})

# Pattern recorded for a minified file such as ``settings.min.json``, which section 7 skips as generated.
MINIFIED_FILE_PATTERN = "*.min.*"

# A base name with ``.min.`` directly before its final extension, after ASCII lowercasing.
_MINIFIED_NAME = re.compile(r"\.min\.[^.]+$")

# Lowercases A-Z only, so every port folds the same names: ``VENDOR`` matches and a non-ASCII look-alike does not.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

# Ignore-decision source labels recorded on every skipped path.
# Shared by the report's ``ignoredPathDetails`` field and ``check-ignore`` so users and agents see *why* a path was skipped.
IGNORE_SOURCE_CONFIG = "config"
IGNORE_SOURCE_GITIGNORE = "gitignore"
IGNORE_SOURCE_DEFAULT = "default"
IGNORE_SOURCE_GENERATED = "generated"


@dataclass(frozen=True, slots=True)
class IgnoreReason:
    """Explain which path policy excluded one discovery candidate.

    The report names the source of the decision so a user can find the relevant policy.
    When known, the matched pattern points to the entry that affected the scan.

    Attributes:
        source: One of ``config``, ``gitignore``, ``default``, or ``generated``.
        pattern: The exact matched glob for ``config``, the matched directory for
            ``default``, or ``None`` for ``gitignore`` (the matcher does not
            surface the matching line).
    """

    source: str
    pattern: str | None = None


@dataclass(frozen=True, slots=True)
class IgnoredPath:
    """Pair an ignored project path with its reason.

    `check-ignore` can explain the same decision the analysis report makes visible.
    The pattern can be absent when the policy has no reported match string.

    Attributes:
        path: Project-relative display path that was skipped.
        source: The ignore source (see :class:`IgnoreReason`).
        pattern: The matched glob/directory/filename, or ``None``.
    """

    path: str
    source: str
    pattern: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Return the JSON-serialisable mapping used by ignoredPathDetails.

        Returns:
            Mapping with path, source and pattern keys; pattern is None when no matched pattern is available.
        """
        return {"path": self.path, "source": self.source, "pattern": self.pattern}


@dataclass(frozen=True, slots=True)
class SourceDiscoveryResult:
    """Carry discovered files and input problems to the analysis runner.

    The runner opens the accepted files and reports which operands were missing or outside the project.
    The ignore entries explain deliberate skips separately from errors.

    Attributes:
        files: Discovered source files that should be analysed.
        missing_paths: Requested input paths that were not found.
        ignored_paths: Requested input paths skipped by ignore handling.
        ignored_path_reasons: The same skipped paths carrying their ignore
            source and matched pattern, one entry per ``ignored_paths`` entry.
        outside_paths: Operands or file links that resolve outside the project root.
    """

    files: tuple[SourceFile, ...]
    missing_paths: tuple[str, ...]
    ignored_paths: tuple[str, ...]
    ignored_path_reasons: tuple[IgnoredPath, ...] = ()
    outside_paths: tuple[str, ...] = ()

    def has_input_errors(self) -> bool:
        """Return whether discovery refused an input.
        The runner uses this to avoid treating an incomplete set of files as a whole-project scan.

        Returns:
            True when discovery found missing paths or paths outside the root.
        """
        return bool(self.missing_paths or self.outside_paths)


@dataclass(frozen=True, slots=True)
class _IgnoreDecision:
    """Record the result of checking one candidate against the path policies.

    Discovery uses the decision to prune a directory or skip a file.
    A reportable skip also carries the display path and the reason the user will see.
    """

    is_ignored: bool
    display_path: str | None = None
    reason: IgnoreReason | None = None


class SourceDiscovery:
    """Walks a project root and emits the ``SourceFile`` set rules should see.

    Honours ``.gitignore``, default-ignored directories, and any
    ``configured_ignore_patterns`` passed at discovery time.
    """

    def __init__(self, project_root: str | Path) -> None:
        self._project_root = Path(project_root).resolve()
        self._gitignore = GitignoreMatcher.from_root(self._project_root)

    def discover(
        self,
        paths: list[str],
        include_ignored: bool = False,
        configured_ignore_patterns: Iterable[str] = (),
    ) -> SourceDiscoveryResult:
        """Find the files to open for the requested scan.
        Return the skips and invalid inputs alongside the files so the report can explain any gaps.

        Args:
            paths: Requested files or directories, absolute or relative to the project root. An empty list or empty path requests the project root.
            include_ignored: True to bypass gitignore and the third-party, minified and fallback exclusions.
                Explicitly requested files bypass those exclusions in either mode. Configured globs and VCS directory exclusions still apply.
            configured_ignore_patterns: Project-config globs that exclude matching paths even when include_ignored is true.

        Returns:
            Discovered source files, missing requests, reported ignores and paths that resolve outside the project. Unsupported types can leave
            the file list empty without a diagnostic.
        """
        patterns = list(configured_ignore_patterns)
        # An invocation with no paths scans the selected project root.
        requested = paths or ["."]
        files: dict[str, SourceFile] = {}
        missing: list[str] = []
        ignored: list[IgnoredPath] = []
        outside: set[str] = set()

        # Each operand can name a file or directory, so keep its input problem separate from the files it yields.
        for raw_path in requested:
            found_paths, missing_path = self._discover_requested_paths(
                raw_path,
                include_ignored=include_ignored,
                patterns=patterns,
                ignored=ignored,
                outside=outside,
            )
            # Report a missing explicit operand by the spelling the caller supplied.
            if missing_path is not None:
                missing.append(missing_path)
            # Overlapping operands can find the same file. `_add_file` keeps a single source entry.
            for found_path in found_paths:
                self._add_file(found_path, files)

        sorted_files = tuple(files[k] for k in sorted(files))
        ignore_reasons_by_path: dict[str, IgnoredPath] = {}
        # Overlapping operands can also skip the same path. Keep the first explanation in the report.
        for entry in ignored:
            ignore_reasons_by_path.setdefault(entry.path, entry)
        reasons = tuple(ignore_reasons_by_path[path] for path in sorted(ignore_reasons_by_path))
        return SourceDiscoveryResult(
            files=sorted_files,
            missing_paths=tuple(sorted(missing)),
            ignored_paths=tuple(reason.path for reason in reasons),
            ignored_path_reasons=reasons,
            outside_paths=tuple(sorted(outside)),
        )

    def classify(
        self,
        raw_path: str,
        *,
        include_ignored: bool = False,
        configured_ignore_patterns: Iterable[str] = (),
    ) -> IgnoredPath | None:
        """Return why gruff would ignore ``raw_path``, or ``None`` if it would not.

        Uses the same ignore rules as discover. For an existing file operand, only configured patterns and VCS directories can exclude it.
        Hypothetical paths retain normal path-policy classification.

        Args:
            raw_path: Absolute or project-relative file or directory path. An empty string selects the project root.
            include_ignored: When true, only configured patterns and VCS directories can exclude the path.
            configured_ignore_patterns: The paths.ignore globs, checked before other exclusion sources.

        Returns:
            The ignored path and its exclusion source and pattern, or None if no exclusion applies. A gitignore match has no reported pattern.
        """
        patterns = list(configured_ignore_patterns)
        absolute = self._absolute_path(raw_path)
        decision = self._ignore_decision(
            absolute,
            include_ignored=include_ignored,
            patterns=patterns,
            record_file=True,
            explicit_file=absolute.is_file(),
        )
        if decision.is_ignored and decision.reason is not None:
            display = decision.display_path or self._display_path(absolute)
            return IgnoredPath(display, decision.reason.source, decision.reason.pattern)
        return None

    def _discover_requested_paths(
        self,
        raw_path: str,
        *,
        include_ignored: bool,
        patterns: list[str],
        ignored: list[IgnoredPath],
        outside: set[str],
    ) -> tuple[Iterable[Path], str | None]:
        """Turn one supplied path into files to scan or a reason it cannot be used.
        An explicitly named file bypasses convenience ignores. Configured paths and VCS directories still apply.
        A directory records ignored entries as discovery walks it.

        Args:
            raw_path: The path as the user supplied it, relative to the project root or absolute; an empty string means the project root. It is
                returned unchanged as the missing path when it does not exist.
            include_ignored: When true, gitignored, third-party, minified and fallback-ignored paths are kept; configured patterns and VCS directories
                still exclude.
            patterns: Configured paths.ignore globs, which exclude a match even when include_ignored is set.
            ignored: Accumulator that receives an IgnoredPath for the operand itself when it is ignored, and for each reported skip as the returned
                directory walk is consumed.
            outside: Accumulator for paths that resolve outside the project.

        Returns:
            A pair of the candidate file paths and the missing path. The paths are empty when the operand is missing, ignored, or neither a file nor a
            directory, a one-item tuple holding the unresolved absolute path for a file whatever its extension, and a lazy walk for a directory. The
            second item is raw_path when the path does not exist and None otherwise.
        """
        absolute = self._absolute_path(raw_path)
        # A deleted file or broken symlink is a missing input, not an empty successful scan.
        if not absolute.exists():
            return (), raw_path
        # A link supplied inside the checkout can still point to a file outside the requested scan boundary.
        if not self._canonical(absolute).is_relative_to(self._project_root):
            outside.add(raw_path)
            return (), None

        decision = self._ignore_decision(
            absolute,
            include_ignored=include_ignored,
            patterns=patterns,
            record_file=True,
            explicit_file=absolute.is_file(),
        )
        # Record a deliberate exclusion separately from an invalid operand.
        if decision.is_ignored:
            self._record_ignored(decision, ignored)
            return (), None

        # Honour a directly supplied file even when its extension would be skipped during directory discovery.
        if absolute.is_file():
            return (absolute,), None
        # Directory operands expand to supported source files as the caller consumes the walk.
        if absolute.is_dir():
            return self._walk(absolute, include_ignored, patterns, ignored, outside), None
        return (), None

    def _walk(
        self,
        directory: Path,
        include_ignored: bool,
        patterns: list[str],
        ignored_paths: list[IgnoredPath],
        outside: set[str],
    ) -> Iterator[Path]:
        """Expand a directory operand into supported files that pass discovery policy.

        Ignored and unreadable subdirectories contribute no files. Symlinked child directories are skipped.
        A symlink to a supported source file outside the project becomes an input error.

        Args:
            directory: Existing directory already checked against ignore rules; it is walked even when it is a symlink.
            include_ignored: Whether gitignored, third-party, minified and fallback-ignored entries are walked as well; configured patterns and VCS
                directories are always skipped.
            patterns: Configured paths.ignore globs checked against each entry.
            ignored_paths: Accumulator that receives an IgnoredPath for every directory the ignore rules skip, and for a skipped file only when it
                matched a configured pattern or is a minified file gruff-py would otherwise scan. A skipped symlinked directory is not recorded.
            outside: Accumulator for file links that point outside the project.

        Yields:
            Each non-ignored file in a listable directory below directory that has a Python or text source type.
        """
        stack: list[Path] = [directory]
        # Walk only directories already accepted by the path policy.
        while stack:
            current = stack.pop()
            # Classify each entry so a skipped directory can be explained without listing all of its descendants.
            for entry in self._directory_entries(current):
                is_dir = entry.is_dir()
                # Skip links that would not yield a supported file. Directory links could also lead back to this walk.
                if entry.is_symlink() and (is_dir or self._source_type(entry) is None or not entry.is_file()):
                    continue
                # Check ignores before external-target containment so excluded symlinks do not abort the scan.
                if self._should_skip_entry(entry, include_ignored, patterns, is_dir, ignored_paths):
                    continue
                # Linked entries accepted by ignore rules must still resolve inside the project root.
                if entry.is_symlink() and not self._canonical(entry).is_relative_to(self._project_root):
                    # Report the link the user can fix without exposing the external target's path.
                    outside.add(self._lexical_display_path(entry))
                    continue
                # Traverse accepted directories, but pass only analysable files to the parser.
                if is_dir:
                    stack.append(entry)
                # A regular file with an unsupported suffix adds no rule input to the scan.
                elif entry.is_file() and self._source_type(entry) is not None:
                    yield entry

    @staticmethod
    def _directory_entries(directory: Path) -> list[Path]:
        """List a directory's entries in a stable sorted order, treating an unreadable directory as empty.

        Args:
            directory: Directory whose immediate children are listed.

        Returns:
            The directory's child paths sorted by path, or an empty list when the directory cannot be read.
        """
        try:
            return sorted(directory.iterdir())
        except OSError:
            return []

    def _should_skip_entry(
        self,
        path: Path,
        include_ignored: bool,
        patterns: list[str],
        is_dir: bool,
        ignored_paths: list[IgnoredPath],
    ) -> bool:
        """Decide whether a walk skips an entry, extending the shared gitignore cache as needed and recording reportable skips.

        Args:
            path: Entry being considered during the walk.
            include_ignored: Whether to bypass gitignore, third-party, minified and fallback exclusions. Configured and VCS exclusions still apply.
            patterns: Configured paths.ignore globs checked against the entry.
            is_dir: Whether the entry is a directory, as already determined by the walk; a skipped directory is always recorded.
            ignored_paths: Accumulator that receives an IgnoredPath when the entry is skipped and its decision carries a display path and reason.

        Returns:
            True when an ignore rule excludes the entry. False when the walk can consider it for traversal or source discovery.
        """
        decision = self._ignore_decision(
            path,
            include_ignored=include_ignored,
            patterns=patterns,
            is_dir=is_dir,
            record_file=False,
        )
        if not decision.is_ignored:
            return False
        self._record_ignored(decision, ignored_paths)
        return True

    @staticmethod
    def _record_ignored(decision: _IgnoreDecision, ignored_paths: list[IgnoredPath]) -> None:
        """Append a skipped path to the ignored-path list when its decision is meant to be reported.

        A decision without a display path or reason, such as one for a gitignored file found during a walk, is dropped without a record.

        Args:
            decision: Ignore decision for a skipped path; it is recorded only when it carries both a display path and a reason.
            ignored_paths: List mutated in place by appending the IgnoredPath built from the decision.

        Returns:
            None. Appends an ignored-path entry when the decision supplies both a display path and a reason.
        """
        if decision.display_path is None or decision.reason is None:
            return
        ignored_paths.append(IgnoredPath(decision.display_path, decision.reason.source, decision.reason.pattern))

    def _add_file(self, path: Path, target: dict[str, SourceFile]) -> None:
        """Register a supported file under its canonical path so repeated discoveries share one entry.

        Unsupported files reaching this helper are dropped without adding a source entry or a diagnostic.

        Args:
            path: File to register; resolution is attempted first, with the original path used if resolution raises OSError.
            target: Mapping from canonical path to SourceFile, updated in place; an existing entry for the same path is replaced.

        Returns:
            None. Inserts or replaces the canonical-path entry for a supported file.
        """
        canonical = self._canonical(path)
        source_type = self._source_type(canonical)
        if source_type is None:
            return
        target[str(canonical)] = SourceFile(
            absolute_path=str(canonical),
            display_path=self._display_path(canonical),
            type=source_type,
        )

    def _absolute_path(self, raw: str) -> Path:
        """Anchor a user-supplied path at the project root without resolving symlinks or collapsing .. segments.

        Args:
            raw: Path as supplied by the user. An empty string selects the project root. An absolute input keeps its own anchor.

        Returns:
            An absolute path for raw that is not resolved, so any .. segments and symlinks remain.
        """
        if raw == "":
            return self._project_root
        candidate = Path(raw)
        if candidate.is_absolute():
            return candidate
        return self._project_root / candidate

    @staticmethod
    def _canonical(path: Path) -> Path:
        """Find the real target when discovery compares a path with the project root.
        Retain the input spelling if the filesystem cannot resolve it so discovery can still make an input decision.

        Args:
            path: Path to resolve.

        Returns:
            The resolved path, or the input path when resolution hits a filesystem error or a symlink loop.
        """
        try:
            return path.resolve()
        except (OSError, RuntimeError):
            # A symlink loop or inaccessible ancestor can prevent resolution before the parser sees a file.
            return path

    def _lexical_display_path(self, path: Path) -> str:
        """Render a candidate path relative to the project root without following a final symlink.

        Args:
            path: File or directory candidate whose parent sits inside the project root.

        Returns:
            Forward-slash relative path using the entry's name when its parent resolves inside the project root; otherwise ``_display_path(path)``.
        """
        # An ordinary file keeps its usual display path.
        if not path.is_symlink():
            return self._display_path(path)
        parent_canonical = self._canonical(path.parent)
        try:
            relative_parent = parent_canonical.relative_to(self._project_root)
        except ValueError:
            # For example, when check-ignore classifies a symlink sitting outside the scanned root, fall back to canonical path rendering.
            return self._display_path(path)
        relative = Path(path.name) if str(relative_parent) == "." else relative_parent / path.name
        return relative.as_posix()

    def _display_path(self, path: Path) -> str:
        """Render a display path for source-file and ignored-path reports, relative to the project root when possible.

        Args:
            path: File or directory to render; resolution is attempted first, so a symlink is shown by its target when resolution succeeds.

        Returns:
            The canonical path relative to the root with forward slashes, . for the root itself, or its string form when outside the root.
            If resolution raises OSError, the original path is used and may retain symlinks or .. segments.
        """
        canonical = self._canonical(path)
        try:
            relative = canonical.relative_to(self._project_root)
        except ValueError:
            return str(canonical)
        text = str(relative).replace("\\", "/")
        return "." if text == "." else text

    def _source_type(self, path: Path) -> SourceFileType | None:
        """Classify a file as Python source, text source, or a file gruff-py does not analyse, from its name alone.

        Args:
            path: File whose extension and base name decide the type; the file is not read and its existence is not checked. Extensions are compared
                case-insensitively.

        Returns:
            python for a .py file. text for a suffix in TEXT_EXTENSIONS, a dotenv-style name, setup.cfg, or a requirements .txt or .in file.
            None for names outside those source types.
        """
        suffix = path.suffix.lower()
        if suffix in PYTHON_EXTENSIONS:
            return "python"
        if suffix in TEXT_EXTENSIONS or self._is_env_like(path) or self._is_dependency_metadata_file(path):
            return "text"
        return None

    @staticmethod
    def _is_env_like(path: Path) -> bool:
        """Recognise dotenv files such as .env and its .env.-prefixed variants by base name.

        Needed alongside the extension check because a bare .env file has no suffix, so the extension list alone never sees it.

        Args:
            path: File whose base name is checked; the comparison is case-sensitive.

        Returns:
            True when the base name is exactly .env or starts with .env., else False.
        """
        name = path.name
        return name == ".env" or name.startswith(".env.")

    @staticmethod
    def _is_dependency_metadata_file(path: Path) -> bool:
        """Recognise Python dependency metadata files, setup.cfg and requirements lists, that are analysed as text.

        Args:
            path: File whose base name is checked case-insensitively.

        Returns:
            True for setup.cfg or a base name that starts with requirements and ends in .txt or .in, else False.
        """
        name = path.name.lower()
        return name in TEXT_FILENAMES or (name.startswith("requirements") and name.endswith((".txt", ".in")))

    def _ignored_component_match(
        self,
        path: Path,
        ignored_names: tuple[str, ...],
        *,
        display_override: str | None = None,
    ) -> str | None:
        """Find which of the given directory names appears as whole components of a path, for the VCS and fallback ignore lists.

        An entry may span several components and must match a contiguous run of them. Matching is case-sensitive and includes the path's final
        component, so a file named exactly like an entry also matches; a path outside the project root is checked across its absolute components.

        Args:
            path: Candidate file or directory, compared through its display path when ``display_override`` is None.
            ignored_names: Directory names to look for, in priority order; the first entry found anywhere on the path wins regardless of where it
                occurs.
            display_override: Precomputed display path (for example, a symlink's lexical in-project path), or None to compute ``_display_path(path)``.

        Returns:
            The first entry of ignored_names found on the path, or None when none matches or the path is the project root.
        """
        display = (display_override if display_override is not None else self._display_path(path)).replace("\\", "/")
        if display == ".":
            return None
        segments = display.strip("/").split("/")
        for ignored in ignored_names:
            ig_segments = ignored.split("/")
            ig_count = len(ig_segments)
            for i in range(0, len(segments) - ig_count + 1):
                if segments[i : i + ig_count] == ig_segments:
                    return ignored
        return None

    def _third_party_match(self, path: Path, *, is_dir: bool, display_override: str | None = None) -> str | None:
        """Return the outermost third-party or build-output directory on path, lowercased.

        For a file, only its ancestor directories count. For example, vendor/dist matches vendor even when dist is a file.
        The outermost directory wins, so vendor/x/dist/y.py is reported as vendor.

        Args:
            path: Candidate whose displayed components are checked, relative to the project root when possible. The root itself has no match.
            is_dir: Whether the candidate itself is a directory, which makes its own name eligible.
            display_override: Precomputed display path (for example, a symlink's lexical in-project path), or None to compute ``_display_path(path)``.

        Returns:
            The matched directory name in lowercase, or None when no directory on the path is in the class.
        """
        display = (display_override if display_override is not None else self._display_path(path)).replace("\\", "/")
        if display == ".":
            return None
        segments = display.strip("/").split("/")
        directories = segments if is_dir else segments[:-1]
        for segment in directories:
            lowered = segment.translate(_ASCII_LOWER)
            if lowered in THIRD_PARTY_DIRECTORIES:
                return lowered
        return None

    def _fallback_applies_at(self, path: Path) -> bool:
        """Decide whether a path is eligible for the built-in fallback directory ignores.

        A .gitignore file along the checked parent chain disables the fallback regardless of its contents.
        A directory's own .gitignore does not affect fallback eligibility for that directory.

        Args:
            path: Candidate file or directory whose ancestor directories are searched for a .gitignore.

        Returns:
            True when the canonical parent is outside the project root or no .gitignore file exists from the root through that parent.
            False when a .gitignore file exists along that chain.
        """
        parent = self._canonical(path.parent)
        try:
            relative_parent = parent.relative_to(self._project_root)
        except ValueError:
            return True

        current = self._project_root
        if (current / ".gitignore").is_file():
            return False
        for segment in relative_parent.parts:
            current /= segment
            if (current / ".gitignore").is_file():
                return False
        return True

    def _configured_pattern(
        self,
        path: Path,
        patterns: list[str],
        *,
        display_override: str | None = None,
    ) -> str | None:
        """Find the first configured paths.ignore glob that matches a path.

        Args:
            path: Candidate file or directory, compared through its display path when ``display_override`` is None.
            patterns: Configured paths.ignore globs in configuration order; an empty list matches nothing.
            display_override: Precomputed display path (for example, a symlink's lexical in-project path), or None to compute ``_display_path(path)``.

        Returns:
            The first matching pattern exactly as configured, or None when no pattern matches.
        """
        if not patterns:
            return None
        display = (display_override if display_override is not None else self._display_path(path)).replace("\\", "/")
        for pattern in patterns:
            if _is_pattern_match(display, pattern):
                return pattern
        return None

    def _ignore_decision(
        self,
        path: Path,
        *,
        include_ignored: bool,
        patterns: list[str],
        is_dir: bool | None = None,
        record_file: bool,
        explicit_file: bool = False,
    ) -> _IgnoreDecision:
        """Choose a path's exclusion using configured, VCS, gitignore, third-party, minified and fallback checks in that order.

        Configured and VCS exclusions always apply; include_ignored and explicit_file bypass later checks.
        Gitignore checks cache ancestor files and misses; walked-file reporting depends on the exclusion source and record_file.

        Args:
            path: Candidate file or directory.
            include_ignored: When true, only configured patterns and VCS directories can exclude the path.
            patterns: Configured paths.ignore globs, checked before every other rule.
            is_dir: Whether the path is a directory; None means stat the path to find out.
            record_file: Whether a skipped file is reported even under rules that stay silent for walked files; true for requested operands and
                check-ignore, false during a walk. Skipped directories and configured-pattern matches are reported either way.
            explicit_file: Whether path is an existing file the user named directly, which exempts it from the same checks as include_ignored.

        Returns:
            An _IgnoreDecision whose is_ignored says whether to skip the path, whose reason names the ignore source and matched pattern or directory
            (pattern None for gitignore), and whose display_path is the path to report or None when the skip is not reported; a kept path carries
            neither.
        """
        display_path = self._lexical_display_path(path)
        # An in-project link is also judged by its target, so a link into an ignored folder such as generated/ stays skipped.
        target_display = self._display_path(path) if path.is_symlink() and self._canonical(path).is_relative_to(self._project_root) else None
        configured = _match_link_or_target(
            lambda display: self._configured_pattern(path, patterns, display_override=display), display_path, target_display
        )
        if configured is not None:
            return _IgnoreDecision(True, display_path, IgnoreReason(IGNORE_SOURCE_CONFIG, configured))
        if is_dir is None:
            is_dir = path.is_dir()
        vcs_match = _match_link_or_target(
            lambda display: self._ignored_component_match(path, VCS_IGNORED_DIRECTORIES, display_override=display), display_path, target_display
        )
        if vcs_match is not None:
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, vcs_match))
        if include_ignored or explicit_file:
            return _IgnoreDecision(False)
        # Check .gitignore on the link's lexical path and, for an in-project link, on its target path too.
        if self._is_link_or_target_gitignored(path, display_path, target_display, is_dir=is_dir):
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_GITIGNORE, None))
        # A gitignore match above names the reason first; unlike the fallback below, the section 7 classes still apply
        # when a .gitignore governs the path, outermost directory before file name.
        third_party = _match_link_or_target(
            lambda display: self._third_party_match(path, is_dir=bool(is_dir), display_override=display), display_path, target_display
        )
        if third_party is not None:
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, third_party))
        if not is_dir and _MINIFIED_NAME.search(path.name.translate(_ASCII_LOWER)):
            # A walked minified file is listed only when gruff-py would otherwise scan it, as FAMILY-CONTRACT.md
            # section 7 requires.
            recorded = display_path if record_file or self._source_type(path) is not None else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, MINIFIED_FILE_PATTERN))
        default_match = _match_link_or_target(
            lambda display: self._ignored_component_match(path, FALLBACK_IGNORED_DIRECTORIES, display_override=display), display_path, target_display
        )
        if default_match is not None and self._fallback_applies_at(path):
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, default_match))
        return _IgnoreDecision(False)

    def _is_link_or_target_gitignored(
        self,
        path: Path,
        display_path: str,
        target_display: str | None,
        *,
        is_dir: bool | None = None,
    ) -> bool:
        """Check whether ``.gitignore`` matches a path as shown or, for an in-project symlink, its resolved target.

        Args:
            path: Candidate file or directory being evaluated during discovery or ``check-ignore``.
            display_path: Lexical in-project display path for a symlink, or canonical display path otherwise.
            target_display: In-project target display path for a symlink, or None for ordinary files and external links.
            is_dir: Whether the entry is a directory, forwarded to gitignore directory-only rules; None stats the path.

        Returns:
            True when ``.gitignore`` ignores either the lexical path or the in-project symlink target; False otherwise.
        """
        # Anchor symlinks at their lexical in-project path so .gitignore matches the link instead of an external target.
        gitignore_path = self._project_root / display_path if path.is_symlink() and not Path(display_path).is_absolute() else path
        if self._is_gitignored(gitignore_path, is_dir=is_dir):
            return True
        if target_display is None or Path(target_display).is_absolute():
            return False
        return self._is_gitignored(self._project_root / target_display, is_dir=is_dir)

    def _is_gitignored(self, path: Path, *, is_dir: bool | None = None) -> bool:
        """Check the project's gitignore rules, caching ancestor specs and missing files as matching reaches new directories.

        Args:
            path: Candidate file or directory.
            is_dir: Whether path is a directory, which lets directory-only gitignore rules match; None means stat the path, treating a stat failure as
                not a directory.

        Returns:
            True when the project's .gitignore rules ignore the path; False otherwise, including for a path outside the project root or one that still
            contains .. segments.
        """
        if is_dir is None:
            try:
                is_dir = path.is_dir()
            except OSError:
                is_dir = False
        return self._gitignore.is_ignored(path, is_dir=is_dir)


def _match_link_or_target(match: Callable[[str], str | None], display_path: str, target_display: str | None) -> str | None:
    """Run one ignore check on a path as shown, then on an in-project link's target when the shown path does not match.

    A link such as ``src/model.py -> generated/model.py`` is skipped when either path is ignored, and is still reported under its own path.

    Args:
        match: Ignore check that takes a display path and returns the matching pattern or directory name, or None.
        display_path: The path as the user sees it, which for a link is the link's own path.
        target_display: The link target's project-relative path, or None for an ordinary file or a link pointing outside the project.

    Returns:
        The first match from the shown path, then from the target; None when neither path is ignored by this check.
    """
    found = match(display_path)
    # Only an in-project link has a second path worth checking.
    if found is None and target_display is not None:
        found = match(target_display)
    return found


def _is_pattern_match(display_path: str, pattern: str) -> bool:
    """Test a display path against one configured paths.ignore glob.

    Literal matches include descendants. Globs use ** across directories and * or ? within a segment.
    Other characters in the normalized pattern are literal. A glob such as **/name requires a slash and misses a root-level name.

    Args:
        display_path: Forward-slash path to test, relative to the project root when possible. Leading and trailing slashes are ignored.
        pattern: Glob or plain path from paths.ignore; outer slashes are ignored and backslashes become forward slashes.

    Returns:
        True when the pattern names the path, one of its ancestor directories, or matches it as a glob, else False.
    """
    normalised_pattern = pattern.replace("\\", "/").strip("/")
    normalised_path = display_path.strip("/")
    if normalised_pattern == normalised_path:
        return True
    if normalised_path.startswith(normalised_pattern + "/"):
        return True
    escaped = re.escape(normalised_pattern)
    regex = "^" + escaped.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
    return re.match(regex, normalised_path) is not None
