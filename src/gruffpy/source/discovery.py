"""Walks a project root and produces the list of ``SourceFile``s the rules will see."""

import re
from collections.abc import Iterable, Iterator
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

# Directories holding third-party copies, and ``dist``, the one build-output name section 7 adds; ``build``,
# ``coverage`` and ``htmlcov`` stay fallback-only. Like the fallback directories above they match at any depth, but
# they are skipped even under a governing .gitignore and compared case-insensitively over ASCII, because a committed
# copy is still someone else's code (FAMILY-CONTRACT.md section 7, amended by precision-floor M04).
THIRD_PARTY_DIRECTORIES: frozenset[str] = frozenset({"bower_components", "dist", "third-party", "third_party", "vendor", "vendors"})

# Pattern recorded for a minified file such as ``settings.min.json``, which section 7 skips as generated.
MINIFIED_FILE_PATTERN = "*.min.*"

# A base name with ``.min.`` directly before its final extension, after ASCII lowercasing.
_MINIFIED_NAME = re.compile(r"\.min\.[^.]+$")

# Lowercases A-Z only, so every port folds the same names: ``VENDOR`` matches and a non-ASCII look-alike does not.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")

# Ignore-decision source labels recorded on every skipped path. Shared by the
# report's ``ignoredPathDetails`` field and the ``check-ignore`` command so a
# coding agent can see *why* a file was skipped, not only that it was.
IGNORE_SOURCE_CONFIG = "config"
IGNORE_SOURCE_GITIGNORE = "gitignore"
IGNORE_SOURCE_DEFAULT = "default"
IGNORE_SOURCE_GENERATED = "generated"


@dataclass(frozen=True, slots=True)
class IgnoreReason:
    """Why a path was excluded, with the matched glob when the source is config.

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
    """A skipped path paired with the reason discovery excluded it.

    Attributes:
        path: Project-relative display path that was skipped.
        source: The ignore source (see :class:`IgnoreReason`).
        pattern: The matched glob/directory/filename, or ``None``.
    """

    path: str
    source: str
    pattern: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Return the JSON-serialisable mapping used by ``ignoredPathDetails``.

        Returns:
            Mapping with ``path``, ``source``, and ``pattern`` keys.
        """
        return {"path": self.path, "source": self.source, "pattern": self.pattern}


@dataclass(frozen=True, slots=True)
class SourceDiscoveryResult:
    """Files and input-path diagnostics produced by source discovery.

    Attributes:
        files: Discovered source files that should be analysed.
        missing_paths: Requested input paths that were not found.
        ignored_paths: Requested input paths skipped by ignore handling.
        ignored_path_reasons: The same skipped paths carrying their ignore
            source and matched pattern, one entry per ``ignored_paths`` entry.
    """

    files: tuple[SourceFile, ...]
    missing_paths: tuple[str, ...]
    ignored_paths: tuple[str, ...]
    ignored_path_reasons: tuple[IgnoredPath, ...] = ()

    def has_input_errors(self) -> bool:
        """Return whether any requested path was missing.

        Returns:
            True when source discovery found missing input paths.
        """
        return bool(self.missing_paths)


@dataclass(frozen=True, slots=True)
class _IgnoreDecision:
    """Whether a path should be skipped, the optional summary path, and the reason."""

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
        """Discover analyzable source files from requested paths.

        Args:
            paths: Requested file or directory paths relative to the project root.
            include_ignored: Whether default and gitignored paths should be included.
            configured_ignore_patterns: Additional project-config ignore patterns.

        Returns:
            Discovered source files plus missing and ignored path summaries.
        """
        patterns = list(configured_ignore_patterns)
        requested = paths or ["."]
        files: dict[str, SourceFile] = {}
        missing: list[str] = []
        ignored: list[IgnoredPath] = []

        for raw_path in requested:
            found_paths, missing_path = self._discover_requested_paths(
                raw_path,
                include_ignored=include_ignored,
                patterns=patterns,
                ignored=ignored,
            )
            if missing_path is not None:
                missing.append(missing_path)
            for found_path in found_paths:
                self._add_file(found_path, files)

        sorted_files = tuple(files[k] for k in sorted(files))
        deduped: dict[str, IgnoredPath] = {}
        for entry in ignored:
            deduped.setdefault(entry.path, entry)
        reasons = tuple(deduped[path] for path in sorted(deduped))
        return SourceDiscoveryResult(
            files=sorted_files,
            missing_paths=tuple(sorted(missing)),
            ignored_paths=tuple(reason.path for reason in reasons),
            ignored_path_reasons=reasons,
        )

    def classify(
        self,
        raw_path: str,
        *,
        include_ignored: bool = False,
        configured_ignore_patterns: Iterable[str] = (),
    ) -> IgnoredPath | None:
        """Return why gruff would ignore ``raw_path``, or ``None`` if it would not.

        Shares ``discover``'s ignore decision so ``check-ignore`` and ``analyse``
        cannot diverge. Existing file operands receive explicit-file semantics;
        hypothetical paths retain path-policy classification.

        Args:
            raw_path: File or directory path relative to the project root.
            include_ignored: Whether default and gitignored paths are in scope.
            configured_ignore_patterns: Project-config ``paths.ignore`` globs.

        Returns:
            The matching ``IgnoredPath`` (path, source, pattern), or ``None``.
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
    ) -> tuple[Iterable[Path], str | None]:
        """Resolve one requested input path into the files it contributes, recording it as ignored or reporting it as missing.

        An existing file operand gets explicit-file semantics, so a file named directly is skipped only by a configured pattern or a VCS directory,
        never by gitignore, third-party, minified or fallback rules. A directory is returned as a lazy walk, so its skipped entries reach ignored only
        as the caller consumes the walk.

        Args:
            raw_path: The path as the user supplied it, relative to the project root or absolute; an empty string means the project root. It is
                returned unchanged as the missing path when it does not exist.
            include_ignored: When true, gitignored, third-party, minified and fallback-ignored paths are kept; configured patterns and VCS directories
                still exclude.
            patterns: Configured paths.ignore globs, which exclude a match even when include_ignored is set.
            ignored: Accumulator that receives an IgnoredPath for the operand itself when it is ignored, and for each reported skip as the returned
                directory walk is consumed.

        Returns:
            A pair of the candidate file paths and the missing path. The paths are empty when the operand is missing, ignored, or neither a file nor a
            directory, a one-item tuple holding the unresolved absolute path for a file whatever its extension, and a lazy walk for a directory. The
            second item is raw_path when the path does not exist and None otherwise.
        """
        absolute = self._absolute_path(raw_path)
        if not absolute.exists():
            return (), raw_path

        decision = self._ignore_decision(
            absolute,
            include_ignored=include_ignored,
            patterns=patterns,
            record_file=True,
            explicit_file=absolute.is_file(),
        )
        if decision.is_ignored:
            self._record_ignored(decision, ignored)
            return (), None

        if absolute.is_file():
            return (absolute,), None
        if absolute.is_dir():
            return self._walk(absolute, include_ignored, patterns, ignored), None
        return (), None

    def _walk(
        self,
        directory: Path,
        include_ignored: bool,
        patterns: list[str],
        ignored_paths: list[IgnoredPath],
    ) -> Iterator[Path]:
        """Walk a directory tree and yield every analysable source file beneath it that the ignore rules do not skip.

        Symlinked directories found during the walk are never followed, although the directory passed in is walked even when it is itself a symlink.
        An ignored directory is pruned whole, so nothing beneath it is visited or recorded. The directory passed in is not itself checked against the
        ignore rules; the caller has already done that. A directory that cannot be listed, including the directory passed in, is treated as empty: its
        files are left out silently and nothing is recorded for it in ignored_paths.

        Args:
            directory: Existing directory to walk.
            include_ignored: Whether gitignored, third-party, minified and fallback-ignored entries are walked as well; configured patterns and VCS
                directories are always skipped.
            patterns: Configured paths.ignore globs checked against each entry.
            ignored_paths: Accumulator that receives an IgnoredPath for every directory the ignore rules skip, and for a skipped file only when it
                matched a configured pattern or is a minified file gruff-py would otherwise scan. A skipped symlinked directory is not recorded.

        Yields:
            Each non-ignored file in a listable directory below directory that has a Python or text source type.
        """
        stack: list[Path] = [directory]
        while stack:
            current = stack.pop()
            for entry in self._directory_entries(current):
                is_dir = entry.is_dir()
                if is_dir and entry.is_symlink():
                    continue
                if self._should_skip_entry(entry, include_ignored, patterns, is_dir, ignored_paths):
                    continue
                if is_dir:
                    stack.append(entry)
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
        """Decide whether the walk skips one directory entry, recording the reason when the skip is reportable.

        Args:
            path: Entry being considered during the walk.
            include_ignored: Whether gitignored, third-party, minified and fallback-ignored entries are kept.
            patterns: Configured paths.ignore globs checked against the entry.
            is_dir: Whether the entry is a directory, as already determined by the walk; a skipped directory is always recorded.
            ignored_paths: Accumulator that receives an IgnoredPath when the entry is skipped and its decision carries a display path and reason.

        Returns:
            True when the entry is ignored and the walk must skip it, False when the walk keeps it.
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
        """
        if decision.display_path is None or decision.reason is None:
            return
        ignored_paths.append(IgnoredPath(decision.display_path, decision.reason.source, decision.reason.pattern))

    def _add_file(self, path: Path, target: dict[str, SourceFile]) -> None:
        """Register a discovered file under its resolved path so the same file reached twice is analysed once.

        A file with no supported source type is dropped silently, so an explicitly named file with an unsupported extension yields no source file and
        no missing or ignored diagnostic.

        Args:
            path: File to register; it is resolved before its source type and display path are computed.
            target: Mapping from resolved absolute path to SourceFile, updated in place; an existing entry for the same resolved path is replaced.
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
        """Anchor a user-supplied path at the project root without resolving symlinks or relative segments.

        Args:
            raw: Path as supplied by the user; an empty string means the project root, and an absolute path is returned unchanged.

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
        """Resolve symlinks and relative segments in a path, falling back to the path as given when resolution raises an OSError.

        Args:
            path: Path to resolve.

        Returns:
            The resolved path, or path unchanged when resolution raises an OSError.
        """
        try:
            return path.resolve()
        except OSError:
            return path

    def _display_path(self, path: Path) -> str:
        """Render a path as the project-relative, forward-slash string used for source files and ignored-path reports.

        Args:
            path: File or directory to render; it is resolved first, so a symlink is shown by its target.

        Returns:
            The resolved path relative to the project root with forward slashes, . for the root itself, or the resolved absolute path when it lies
            outside the project root.
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
            python for a .py file; text for a configuration-style extension, a dotenv-style name, setup.cfg, or a requirements .txt or .in file; None
            when the file is not analysed.
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

    def _ignored_component_match(self, path: Path, ignored_names: tuple[str, ...]) -> str | None:
        """Find which of the given directory names appears as whole components of a path, for the VCS and fallback ignore lists.

        An entry may span several components and must match a contiguous run of them. Matching is case-sensitive and includes the path's final
        component, so a file named exactly like an entry also matches; a path outside the project root is checked across its absolute components.

        Args:
            path: Candidate file or directory, compared through its display path.
            ignored_names: Directory names to look for, in priority order; the first entry found anywhere on the path wins regardless of where it
                occurs.

        Returns:
            The first entry of ignored_names found on the path, or None when none matches or the path is the project root.
        """
        display = self._display_path(path).replace("\\", "/")
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

    def _third_party_match(self, path: Path, *, is_dir: bool) -> str | None:
        """Return the outermost third-party or build-output directory on ``path``, lowercased.

        A file's own name is not a directory, so a file called ``dist`` never matches, while ``a/Vendor/x.py`` gives
        ``vendor``. The outermost directory wins, so ``vendor/x/dist/y.py`` is reported as ``vendor`` in every port.

        Args:
            path: Candidate file or directory.
            is_dir: Whether the candidate itself is a directory, which makes its own name eligible.

        Returns:
            The matched directory name in lowercase, or ``None`` when no directory on the path is in the class.
        """
        display = self._display_path(path).replace("\\", "/")
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
        """Decide whether the built-in fallback ignore directories apply to a path, which they do only when no .gitignore governs it.

        A .gitignore at the project root or in any directory down to and including the path's parent disables the fallback, leaving the fallback
        directory names to the .gitignore rules. A directory's own .gitignore is not consulted for the directory itself.

        Args:
            path: Candidate file or directory whose ancestor directories are searched for a .gitignore.

        Returns:
            True when no .gitignore exists from the project root down to the path's parent, or when the parent lies outside the project root; False
            otherwise.
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

    def _configured_pattern(self, path: Path, patterns: list[str]) -> str | None:
        """Find the first configured paths.ignore glob that matches a path.

        Args:
            path: Candidate file or directory, compared through its resolved display path, which is absolute when the path lies outside the project
                root.
            patterns: Configured paths.ignore globs in configuration order; an empty list matches nothing.

        Returns:
            The first matching pattern exactly as configured, or None when no pattern matches.
        """
        if not patterns:
            return None
        display = self._display_path(path).replace("\\", "/")
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
        """Decide whether discovery skips a path, and why, by checking each exclusion source in a fixed order.

        The order is configured patterns, VCS directories, gitignore, third-party directories, minified files, then fallback directories. Configured
        patterns and VCS directories always apply. When include_ignored or explicit_file is set, evaluation stops there, so the gitignore,
        third-party, minified and fallback checks never exclude an existing file the user named directly, nor any path when ignored paths were
        requested.

        The decision's display path is None when the skip stays out of the report: a walked file skipped by a VCS, gitignore, third-party or fallback
        rule, or a walked minified file with no analysable source type.

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
        display_path = self._display_path(path)
        configured = self._configured_pattern(path, patterns)
        if configured is not None:
            return _IgnoreDecision(True, display_path, IgnoreReason(IGNORE_SOURCE_CONFIG, configured))
        if is_dir is None:
            is_dir = path.is_dir()
        vcs_match = self._ignored_component_match(path, VCS_IGNORED_DIRECTORIES)
        if vcs_match is not None:
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, vcs_match))
        if include_ignored or explicit_file:
            return _IgnoreDecision(False)
        if self._is_gitignored(path, is_dir=is_dir):
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_GITIGNORE, None))
        # A gitignore match above names the reason first; unlike the fallback below, the section 7 classes still apply
        # when a .gitignore governs the path, outermost directory before file name.
        third_party = self._third_party_match(path, is_dir=is_dir)
        if third_party is not None:
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, third_party))
        if not is_dir and _MINIFIED_NAME.search(path.name.translate(_ASCII_LOWER)):
            # A walked minified file is listed only when gruff-py would otherwise scan it, as FAMILY-CONTRACT.md
            # section 7 requires.
            recorded = display_path if record_file or self._source_type(path) is not None else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, MINIFIED_FILE_PATTERN))
        default_match = self._ignored_component_match(path, FALLBACK_IGNORED_DIRECTORIES)
        if default_match is not None and self._fallback_applies_at(path):
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, default_match))
        return _IgnoreDecision(False)

    def _is_gitignored(self, path: Path, *, is_dir: bool | None = None) -> bool:
        """Ask the project's gitignore matcher whether a path is ignored.

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


def _is_pattern_match(display_path: str, pattern: str) -> bool:
    """Test a project-relative display path against one configured paths.ignore glob.

    A pattern matches when, compared literally, it equals the path or names one of its ancestor directories, or when the whole path matches it as a
    glob in which ** crosses directories, * and ? stay within one segment, and every other character is literal. Leading and trailing slashes are
    ignored and backslashes in the pattern become forward slashes. Because ** followed by a slash still needs that slash, such a pattern does not
    match a name at the project root.

    Args:
        display_path: Project-relative forward-slash path to test.
        pattern: Configured glob or plain path as written in paths.ignore.

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
