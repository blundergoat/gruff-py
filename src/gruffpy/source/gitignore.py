"""Reads and applies project ``.gitignore`` files for source discovery."""

from dataclasses import dataclass, field
from pathlib import Path

from pathspec import GitIgnoreSpec


def _load_spec(directory: Path) -> GitIgnoreSpec | None:
    """Parse the .gitignore file that sits directly in a directory into a spec the matcher can apply.

    Undecodable bytes are replaced rather than rejected, so a file with a bad encoding still loads.

    Args:
        directory: Directory whose own .gitignore file is read; parent and child directories are not consulted.

    Returns:
        Spec built from the file's lines, or None when the directory has no .gitignore file or reading it fails with an OSError.
    """
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
        if any(part == ".." for part in rel.parts):
            return False

        applicable_dirs = [self.root]
        current_dir = self.root
        for part in rel.parts[:-1]:
            ancestor = current_dir / part
            ancestor_is_ignored = None
            for gitignore_dir in applicable_dirs:
                ancestor_is_ignored = self._is_ignored_by_spec(gitignore_dir, ancestor, is_dir=True, prior=ancestor_is_ignored)
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
        """Apply one directory's loaded .gitignore to a path, keeping the verdict from shallower files when this one does not decide.

        Called for each applicable directory from the root downward, so a deeper file's verdict replaces a shallower one only when this spec decides
        the path.

        Args:
            gitignore_dir: Directory whose cached .gitignore spec is consulted; a directory with no loaded spec leaves the verdict unchanged.
            abs_path: Absolute path being checked, made relative to gitignore_dir before matching.
            is_dir: Whether the path is matched as a directory, so directory-only patterns such as build/ can apply.
            prior: Verdict from shallower .gitignore files; None means no shallower spec has decided the path.

        Returns:
            True when this spec ignores the path, False when a negation pattern re-includes it, or prior unchanged when gitignore_dir has no spec, the
            path is outside or equal to gitignore_dir, no pattern matches, or a directory is matched only by a contents-only /** pattern.
        """
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
        """Ask one gitignore spec for its verdict on a relative path, treating a directory matched only by a trailing /** as undecided.

        pathspec matches a pattern such as build/** against the trailing-slash form of the build directory itself, while git applies it only to what
        is inside; that case returns None so the directory is not ignored as a whole.

        Args:
            spec: Parsed .gitignore spec to check against.
            rel_str: Forward-slash path relative to the spec's directory, without a trailing slash.
            is_dir: Whether the path is a directory; when set, a trailing slash is added before matching, and an ignore verdict that comes only from a
                contents-only /** match is treated as undecided.

        Returns:
            True when the deciding pattern ignores the path, False when a negation pattern re-includes it, or None when no pattern matches, or when a
            directory is ignored only by a deciding pattern ending in /** and the path without its trailing slash matches no pattern.
        """
        result = spec.check_file(_match_path(rel_str, is_dir))
        if result.include is None:
            return None
        if is_dir and result.include is True and GitignoreMatcher._is_directory_match_contents_only(spec, rel_str, result.index):
            return None
        return bool(result.include)

    @staticmethod
    def _is_directory_match_contents_only(
        spec: GitIgnoreSpec,
        rel_str: str,
        pattern_index: int | None,
    ) -> bool:
        """Detect a directory whose match was decided by a pattern ending in /**, which git applies to its contents rather than itself.

        Args:
            spec: Parsed .gitignore spec that produced the directory match.
            rel_str: Directory path relative to the spec's directory, without a trailing slash, rechecked to see whether any pattern matches it on its
                own.
            pattern_index: Index into the spec's patterns of the pattern that decided the trailing-slash match; None means no pattern decided.

        Returns:
            True when the path without its trailing slash matches nothing and the deciding pattern, ignoring a leading !, ends with /**; False
            otherwise, including when pattern_index is None.
        """
        if pattern_index is None:
            return False
        without_slash = spec.check_file(rel_str)
        if without_slash.include is not None:
            return False
        pattern = spec.patterns[pattern_index].pattern
        return isinstance(pattern, str) and pattern.lstrip("!").endswith("/**")

    def _ensure_loaded(self, directory: Path) -> None:
        """Load and cache a directory's .gitignore the first time the matcher reaches that directory, so each file is read at most once.

        The directory is recorded as loaded even when it has no readable .gitignore, so a missing file is not looked up again; only directories with a
        spec are added to the spec cache.

        Args:
            directory: Directory whose .gitignore should be loaded if it has not been checked already.
        """
        if directory in self._loaded_dirs:
            return
        self._loaded_dirs.add(directory)
        spec = _load_spec(directory)
        if spec is not None:
            self._specs_by_dir[directory] = spec


def _relative_gitignore_path(abs_path: Path, gitignore_dir: Path) -> str | None:
    """Express a path relative to a .gitignore's directory in the forward-slash form gitignore patterns are matched against.

    Args:
        abs_path: Absolute path being checked.
        gitignore_dir: Directory holding the .gitignore whose patterns the path will be matched against.

    Returns:
        Relative path with backslashes converted to forward slashes, or None when the path is outside gitignore_dir or is gitignore_dir itself,
        meaning that .gitignore has no say.
    """
    try:
        rel = abs_path.relative_to(gitignore_dir)
    except ValueError:
        return None
    rel_str = str(rel).replace("\\", "/")
    if not rel_str or rel_str == ".":
        return None
    return rel_str


def _match_path(rel_str: str, is_dir: bool) -> str:
    """Add the trailing slash that marks a directory, so directory-only gitignore patterns such as build/ can match it.

    Args:
        rel_str: Forward-slash path relative to the .gitignore's directory.
        is_dir: Whether the path is a directory; when False the path is returned unchanged.

    Returns:
        rel_str with one trailing slash when is_dir is set and it does not already end in a slash; otherwise rel_str unchanged.
    """
    if is_dir and not rel_str.endswith("/"):
        return f"{rel_str}/"
    return rel_str
