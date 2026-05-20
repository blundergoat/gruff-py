"""Reads and applies project ``.gitignore`` files for source discovery."""

from dataclasses import dataclass, field
from pathlib import Path

from pathspec import GitIgnoreSpec


def _load_spec(directory: Path) -> GitIgnoreSpec | None:
    gitignore = directory / ".gitignore"
    if not gitignore.is_file():
        return None
    try:
        content = gitignore.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return GitIgnoreSpec.from_lines(content.splitlines())


@dataclass(frozen=True, slots=True)
class GitignoreMatcher:
    """Resolves whether a path is gitignored under a given project root.

    Loads ``.gitignore`` files on demand as paths are checked and applies them
    with git's nested-gitignore precedence: deeper files override shallower
    ones, and the deepest matching pattern decides.
    """

    root: Path
    _specs_by_dir: dict[Path, GitIgnoreSpec] = field(default_factory=dict)
    _loaded_dirs: set[Path] = field(default_factory=set)

    @classmethod
    def from_root(cls, root: Path) -> "GitignoreMatcher":
        """Create a matcher rooted at a project directory.

        Args:
            root: Project root whose nested ``.gitignore`` files should apply.

        Returns:
            Matcher with the root ``.gitignore`` loaded when present.
        """
        resolved = root.resolve() if root.exists() else root
        matcher = cls(root=resolved)
        matcher._ensure_loaded(resolved)
        return matcher

    def has_rules(self) -> bool:
        """Return whether any gitignore rules have been loaded.

        Returns:
            True when at least one applicable ``.gitignore`` file was found.
        """
        return bool(self._specs_by_dir)

    def is_ignored(self, path: Path, *, is_dir: bool = False) -> bool:
        """Return whether a path is excluded by project gitignore rules.

        ``is_dir`` should be set when the path refers to a directory so
        trailing-slash patterns like ``build/`` match correctly.

        Args:
            path: File or directory path to check.
            is_dir: Whether the path should be matched as a directory.

        Returns:
            True when the path is ignored by the applicable gitignore stack.
        """
        abs_path = path if path.is_absolute() else self.root / path
        try:
            rel = abs_path.relative_to(self.root)
        except ValueError:
            return False

        applicable_dirs = [self.root]
        current_dir = self.root
        for part in rel.parts[:-1]:
            ancestor = current_dir / part
            ancestor_is_ignored = None
            for gitignore_dir in applicable_dirs:
                ancestor_is_ignored = self._is_ignored_by_spec(
                    gitignore_dir, ancestor, is_dir=True, prior=ancestor_is_ignored
                )
            if ancestor_is_ignored is True:
                return True
            current_dir = ancestor
            self._ensure_loaded(current_dir)
            if current_dir in self._specs_by_dir:
                applicable_dirs.append(current_dir)

        is_ignored: bool | None = None
        for gitignore_dir in applicable_dirs:
            is_ignored = self._is_ignored_by_spec(gitignore_dir, abs_path, is_dir, is_ignored)
        return is_ignored is True

    def _is_ignored_by_spec(
        self,
        gitignore_dir: Path,
        abs_path: Path,
        is_dir: bool,
        prior: bool | None,
    ) -> bool | None:
        spec = self._specs_by_dir.get(gitignore_dir)
        if spec is None:
            return prior
        rel_str = _relative_gitignore_path(abs_path, gitignore_dir)
        if rel_str is None:
            return prior
        is_ignored = self._is_spec_ignored(spec, rel_str, is_dir)
        if is_ignored is None:
            return prior
        return is_ignored

    @staticmethod
    def _is_spec_ignored(
        spec: GitIgnoreSpec,
        rel_str: str,
        is_dir: bool,
    ) -> bool | None:
        result = spec.check_file(_match_path(rel_str, is_dir))
        if result.include is None:
            return None
        if (
            is_dir
            and result.include is True
            and GitignoreMatcher._is_directory_match_contents_only(spec, rel_str, result.index)
        ):
            return None
        return bool(result.include)

    @staticmethod
    def _is_directory_match_contents_only(
        spec: GitIgnoreSpec,
        rel_str: str,
        pattern_index: int | None,
    ) -> bool:
        if pattern_index is None:
            return False
        without_slash = spec.check_file(rel_str)
        if without_slash.include is not None:
            return False
        pattern = spec.patterns[pattern_index].pattern
        return isinstance(pattern, str) and pattern.lstrip("!").endswith("/**")

    def _ensure_loaded(self, directory: Path) -> None:
        if directory in self._loaded_dirs:
            return
        self._loaded_dirs.add(directory)
        spec = _load_spec(directory)
        if spec is not None:
            self._specs_by_dir[directory] = spec


def _relative_gitignore_path(abs_path: Path, gitignore_dir: Path) -> str | None:
    try:
        rel = abs_path.relative_to(gitignore_dir)
    except ValueError:
        return None
    rel_str = str(rel).replace("\\", "/")
    if not rel_str or rel_str == ".":
        return None
    return rel_str


def _match_path(rel_str: str, is_dir: bool) -> str:
    if is_dir and not rel_str.endswith("/"):
        return f"{rel_str}/"
    return rel_str
