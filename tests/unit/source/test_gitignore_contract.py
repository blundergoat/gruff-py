"""Contract test asserting ``GitignoreMatcher`` agrees with ``git check-ignore``.

Spins up an isolated git repo in ``tmp_path``, writes a representative
``.gitignore`` corpus, then asserts ``git check-ignore`` and the matcher
return the same verdict for every probed path.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

from gruff.source.gitignore import GitignoreMatcher

_GIT = shutil.which("git")


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _git_check_ignored(repo: Path, target: Path) -> bool:
    """Return True iff ``git check-ignore`` says *target* is ignored in *repo*."""
    assert _GIT is not None
    result = subprocess.run(
        [_GIT, "-C", str(repo), "check-ignore", "-q", str(target.relative_to(repo))],
        capture_output=True,
    )
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise RuntimeError(f"git check-ignore failed with rc={result.returncode}: {result.stderr!r}")


def _init_repo(root: Path) -> None:
    assert _GIT is not None
    subprocess.run(
        [_GIT, "init", "--quiet", str(root)],
        check=True,
        capture_output=True,
    )


_PROBES: tuple[tuple[str, bool], ...] = (
    # path relative to root, is_dir
    ("app.py", False),
    ("ignored.bin", False),
    ("keep.bin", False),
    ("build", True),
    ("build/out.py", False),
    ("pkg/build", True),
    ("pkg/build/out.py", False),
    ("pkg/.gitignore", False),
    ("pkg/keep.bin", False),
    ("pkg/noise.bin", False),
    ("vendor", True),
    ("vendor/keep.py", False),
    ("anchored/build", True),
    ("anchored/build/out.py", False),
    ("docs/notes.md", False),
    ("docs/temp/cache.txt", False),
    ("a/temp/file.py", False),
    ("b/deep/temp/file.py", False),
)


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Create a representative gitignore corpus in *tmp_path* and return its root."""
    _write(
        tmp_path / ".gitignore",
        "\n".join(
            [
                "*.bin",
                "!keep.bin",
                "build/",
                "/anchored/build/",
                "**/temp/",
                "vendor/",
                "",
            ]
        ),
    )
    _write(tmp_path / "pkg" / ".gitignore", "noise.bin\nkeep.bin\n")
    _write(tmp_path / "vendor" / ".gitignore", "!keep.py\n")

    _write(tmp_path / "app.py")
    _write(tmp_path / "ignored.bin")
    _write(tmp_path / "keep.bin")
    (tmp_path / "build").mkdir()
    _write(tmp_path / "build" / "out.py")
    (tmp_path / "pkg" / "build").mkdir(parents=True)
    _write(tmp_path / "pkg" / "build" / "out.py")
    _write(tmp_path / "pkg" / "keep.bin")
    _write(tmp_path / "pkg" / "noise.bin")
    _write(tmp_path / "vendor" / "keep.py")
    (tmp_path / "anchored" / "build").mkdir(parents=True)
    _write(tmp_path / "anchored" / "build" / "out.py")
    _write(tmp_path / "docs" / "notes.md")
    (tmp_path / "docs" / "temp").mkdir(parents=True)
    _write(tmp_path / "docs" / "temp" / "cache.txt")
    (tmp_path / "a" / "temp").mkdir(parents=True)
    _write(tmp_path / "a" / "temp" / "file.py")
    (tmp_path / "b" / "deep" / "temp").mkdir(parents=True)
    _write(tmp_path / "b" / "deep" / "temp" / "file.py")
    return tmp_path


@pytest.mark.skipif(_GIT is None, reason="git is not available on PATH")
def test_matcher_matches_git_check_ignore_on_corpus(corpus: Path) -> None:
    _init_repo(corpus)
    matcher = GitignoreMatcher.from_root(corpus)

    disagreements: list[str] = []
    for rel, is_dir in _PROBES:
        target = corpus / rel
        git_verdict = _git_check_ignored(corpus, target)
        matcher_verdict = matcher.is_ignored(target, is_dir=is_dir)
        if git_verdict != matcher_verdict:
            disagreements.append(
                f"  {rel} (is_dir={is_dir}): git={git_verdict} matcher={matcher_verdict}"
            )

    assert not disagreements, "GitignoreMatcher disagrees with git check-ignore:\n" + "\n".join(
        disagreements
    )
