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
            resolved = abs_path.resolve()
            rel = resolved.relative_to(self.root)
        except (ValueError, OSError):
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
            is_ignored = self._is_ignored_by_spec(gitignore_dir, resolved, is_dir, is_ignored)
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
        try:
            rel = abs_path.relative_to(gitignore_dir)
        except ValueError:
            return prior
        rel_str = str(rel).replace("\\", "/")
        if not rel_str or rel_str == ".":
            return prior
        if is_dir and not rel_str.endswith("/"):
            rel_str += "/"
        result = spec.check_file(rel_str)
        if result.include is None:
            return prior
        return bool(result.include)

    def _ensure_loaded(self, directory: Path) -> None:
        if directory in self._loaded_dirs:
            return
        self._loaded_dirs.add(directory)
        spec = _load_spec(directory)
        if spec is not None:
            self._specs_by_dir[directory] = spec
