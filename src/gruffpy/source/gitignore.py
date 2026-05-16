"""Reads and applies project ``.gitignore`` files for source discovery."""

from dataclasses import dataclass, field
from pathlib import Path

from pathspec import GitIgnoreSpec


def _load_specs(root: Path) -> dict[Path, GitIgnoreSpec]:
    specs: dict[Path, GitIgnoreSpec] = {}
    if not root.exists():
        return specs
    for gitignore in root.rglob(".gitignore"):
        if not gitignore.is_file():
            continue
        try:
            content = gitignore.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            parent = gitignore.parent.resolve()
        except OSError:
            continue
        specs[parent] = GitIgnoreSpec.from_lines(content.splitlines())
    return specs


@dataclass(frozen=True, slots=True)
class GitignoreMatcher:
    """Resolves whether a path is gitignored under a given project root.

    Loads every reachable ``.gitignore`` once at construction and applies
    them with git's nested-gitignore precedence: deeper files override
    shallower ones, and the deepest matching pattern decides.
    """

    root: Path
    _specs_by_dir: dict[Path, GitIgnoreSpec] = field(default_factory=dict)

    @classmethod
    def from_root(cls, root: Path) -> "GitignoreMatcher":
        resolved = root.resolve() if root.exists() else root
        return cls(root=resolved, _specs_by_dir=_load_specs(resolved))

    def has_rules(self) -> bool:
        return bool(self._specs_by_dir)

    def is_ignored(self, path: Path, *, is_dir: bool = False) -> bool:
        """Return True iff *path* is excluded by the project's gitignore rules.

        ``is_dir`` should be set when the path refers to a directory so
        trailing-slash patterns like ``build/`` match correctly.
        """
        if not self._specs_by_dir:
            return False

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
            ancestor_decision = None
            for gitignore_dir in applicable_dirs:
                ancestor_decision = self._evaluate(
                    gitignore_dir, ancestor, is_dir=True, prior=ancestor_decision
                )
            if ancestor_decision is True:
                return True
            current_dir = ancestor
            if current_dir in self._specs_by_dir:
                applicable_dirs.append(current_dir)

        decision: bool | None = None
        for gitignore_dir in applicable_dirs:
            decision = self._evaluate(gitignore_dir, resolved, is_dir, decision)
        return decision is True

    def _evaluate(
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
