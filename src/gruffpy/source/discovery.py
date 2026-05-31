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

IGNORED_FILENAMES: frozenset[str] = frozenset(
    {
        # Python lockfiles / package metadata that routinely contain high-entropy
        # hashes (sha256 integrity blobs) that look like secrets.
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "composer.lock",
        "Cargo.lock",
        "go.sum",
    }
)

DEFAULT_IGNORED_DIRECTORIES: tuple[str, ...] = (
    ".fleet",
    ".git",
    ".goat-flow/logs",
    ".goat-flow/scratchpad",
    ".goat-flow/tasks",
    ".hg",
    ".idea",
    ".mypy_cache",
    ".pyre",
    ".pytest_cache",
    ".pytype",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "cache",
    "coverage",
    "dist",
    "generated",
    "htmlcov",
    "node_modules",
    "tmp",
    "vendor",
    "venv",
)

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
            ``default``, the lockfile name for ``generated``, or ``None`` for
            ``gitignore`` (the matcher does not surface the matching line).
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
        cannot diverge, then adds the generated-lockfile check that discovery
        otherwise applies through source-type filtering. Works on hypothetical
        paths that do not exist on disk, mirroring ``git check-ignore``.

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
        )
        if decision.is_ignored and decision.reason is not None:
            display = decision.display_path or self._display_path(absolute)
            return IgnoredPath(display, decision.reason.source, decision.reason.pattern)
        if absolute.name in IGNORED_FILENAMES:
            return IgnoredPath(self._display_path(absolute), IGNORE_SOURCE_GENERATED, absolute.name)
        return None

    def _discover_requested_paths(
        self,
        raw_path: str,
        *,
        include_ignored: bool,
        patterns: list[str],
        ignored: list[IgnoredPath],
    ) -> tuple[Iterable[Path], str | None]:
        absolute = self._absolute_path(raw_path)
        if not absolute.exists():
            return (), raw_path

        decision = self._ignore_decision(
            absolute,
            include_ignored=include_ignored,
            patterns=patterns,
            record_file=True,
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
        if decision.display_path is None or decision.reason is None:
            return
        ignored_paths.append(
            IgnoredPath(decision.display_path, decision.reason.source, decision.reason.pattern)
        )

    def _add_file(self, path: Path, target: dict[str, SourceFile]) -> None:
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
        if raw == "":
            return self._project_root
        candidate = Path(raw)
        if candidate.is_absolute():
            return candidate
        return self._project_root / candidate

    @staticmethod
    def _canonical(path: Path) -> Path:
        try:
            return path.resolve()
        except OSError:
            return path

    def _display_path(self, path: Path) -> str:
        canonical = self._canonical(path)
        try:
            relative = canonical.relative_to(self._project_root)
        except ValueError:
            return str(canonical)
        text = str(relative).replace("\\", "/")
        return "." if text == "." else text

    def _source_type(self, path: Path) -> SourceFileType | None:
        if path.name in IGNORED_FILENAMES:
            return None
        suffix = path.suffix.lower()
        if suffix in PYTHON_EXTENSIONS:
            return "python"
        if (
            suffix in TEXT_EXTENSIONS
            or self._is_env_like(path)
            or self._is_dependency_metadata_file(path)
        ):
            return "text"
        return None

    @staticmethod
    def _is_env_like(path: Path) -> bool:
        name = path.name
        return name == ".env" or name.startswith(".env.")

    @staticmethod
    def _is_dependency_metadata_file(path: Path) -> bool:
        name = path.name.lower()
        return name in TEXT_FILENAMES or (
            name.startswith("requirements") and name.endswith((".txt", ".in"))
        )

    def _default_ignored_match(self, path: Path) -> str | None:
        display = self._display_path(path).replace("\\", "/")
        if display == ".":
            return None
        segments = display.strip("/").split("/")
        for ignored in DEFAULT_IGNORED_DIRECTORIES:
            ig_segments = ignored.split("/")
            ig_count = len(ig_segments)
            for i in range(0, len(segments) - ig_count + 1):
                if segments[i : i + ig_count] == ig_segments:
                    return ignored
        return None

    def _configured_pattern(self, path: Path, patterns: list[str]) -> str | None:
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
    ) -> _IgnoreDecision:
        display_path = self._display_path(path)
        configured = self._configured_pattern(path, patterns)
        if configured is not None:
            return _IgnoreDecision(
                True, display_path, IgnoreReason(IGNORE_SOURCE_CONFIG, configured)
            )
        if include_ignored:
            return _IgnoreDecision(False)
        if is_dir is None:
            is_dir = path.is_dir()
        default_match = self._default_ignored_match(path)
        if default_match is not None:
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(
                True, recorded, IgnoreReason(IGNORE_SOURCE_DEFAULT, default_match)
            )
        if self._is_gitignored(path, is_dir=is_dir):
            recorded = display_path if record_file or is_dir else None
            return _IgnoreDecision(True, recorded, IgnoreReason(IGNORE_SOURCE_GITIGNORE, None))
        return _IgnoreDecision(False)

    def _is_gitignored(self, path: Path, *, is_dir: bool | None = None) -> bool:
        if is_dir is None:
            try:
                is_dir = path.is_dir()
            except OSError:
                is_dir = False
        return self._gitignore.is_ignored(path, is_dir=is_dir)


def _is_pattern_match(display_path: str, pattern: str) -> bool:
    normalised_pattern = pattern.replace("\\", "/").strip("/")
    normalised_path = display_path.strip("/")
    if normalised_pattern == normalised_path:
        return True
    if normalised_path.startswith(normalised_pattern + "/"):
        return True
    escaped = re.escape(normalised_pattern)
    regex = (
        "^" + escaped.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]") + "$"
    )
    return re.match(regex, normalised_path) is not None
