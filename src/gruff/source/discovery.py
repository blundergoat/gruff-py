import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from gruff.source.source_file import SourceFile, SourceFileType

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


@dataclass(frozen=True, slots=True)
class SourceDiscoveryResult:
    files: tuple[SourceFile, ...]
    missing_paths: tuple[str, ...]
    ignored_paths: tuple[str, ...]

    def has_input_errors(self) -> bool:
        return bool(self.missing_paths)


class SourceDiscovery:
    def __init__(self, project_root: str | Path) -> None:
        self._project_root = Path(project_root).resolve()

    def discover(
        self,
        paths: list[str],
        include_ignored: bool = False,
        configured_ignore_patterns: Iterable[str] = (),
    ) -> SourceDiscoveryResult:
        patterns = list(configured_ignore_patterns)
        requested = paths or ["."]
        files: dict[str, SourceFile] = {}
        missing: list[str] = []
        ignored: list[str] = []

        for raw_path in requested:
            absolute = self._absolute_path(raw_path)
            if not absolute.exists():
                missing.append(raw_path)
                continue
            if self._is_configured_ignored(absolute, patterns):
                ignored.append(self._display_path(absolute))
                continue
            if not include_ignored and self._is_default_ignored(absolute):
                ignored.append(self._display_path(absolute))
                continue

            if absolute.is_file():
                self._add_file(absolute, files)
                continue
            if absolute.is_dir():
                for found in self._walk(absolute, include_ignored, patterns, ignored):
                    self._add_file(found, files)

        sorted_files = tuple(files[k] for k in sorted(files))
        return SourceDiscoveryResult(
            files=sorted_files,
            missing_paths=tuple(sorted(missing)),
            ignored_paths=tuple(sorted(set(ignored))),
        )

    def _walk(
        self,
        directory: Path,
        include_ignored: bool,
        patterns: list[str],
        ignored_paths: list[str],
    ) -> Iterator[Path]:
        stack: list[Path] = [directory]
        while stack:
            current = stack.pop()
            try:
                entries = sorted(current.iterdir())
            except OSError:
                continue
            for entry in entries:
                if self._is_configured_ignored(entry, patterns):
                    ignored_paths.append(self._display_path(entry))
                    continue
                if not include_ignored and self._is_default_ignored(entry):
                    if entry.is_dir():
                        ignored_paths.append(self._display_path(entry))
                    continue
                if entry.is_dir():
                    stack.append(entry)
                elif entry.is_file() and self._source_type(entry) is not None:
                    yield entry

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
        suffix = path.suffix.lower()
        if suffix in PYTHON_EXTENSIONS:
            return "python"
        if suffix in TEXT_EXTENSIONS or self._is_env_like(path):
            return "text"
        return None

    @staticmethod
    def _is_env_like(path: Path) -> bool:
        name = path.name
        return name == ".env" or name.startswith(".env.")

    def _is_default_ignored(self, path: Path) -> bool:
        display = self._display_path(path).replace("\\", "/")
        if display == ".":
            return False
        segments = display.strip("/").split("/")
        for ignored in DEFAULT_IGNORED_DIRECTORIES:
            ig_segments = ignored.split("/")
            ig_count = len(ig_segments)
            for i in range(0, len(segments) - ig_count + 1):
                if segments[i : i + ig_count] == ig_segments:
                    return True
        return False

    def _is_configured_ignored(self, path: Path, patterns: list[str]) -> bool:
        if not patterns:
            return False
        display = self._display_path(path).replace("\\", "/")
        return any(_matches_pattern(display, p) for p in patterns)


def _matches_pattern(display_path: str, pattern: str) -> bool:
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
