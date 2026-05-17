"""Contract test asserting ``GitignoreMatcher`` agrees with ``git check-ignore``.

Spins up an isolated git repo in ``tmp_path``, writes a representative
``.gitignore`` corpus, then asserts ``git check-ignore`` and the matcher
return the same verdict for every probed path.
"""

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

from gruffpy.source.gitignore import GitignoreMatcher

_GIT = shutil.which("git")


@dataclass(frozen=True, slots=True)
class _PathProbe:
    rel: str
    is_dir: bool


def _write(path: Path, text: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _is_git_ignored(repo: Path, target: Path) -> bool:
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


_PATH_PROBES: tuple[_PathProbe, ...] = (
    # path relative to root, is_dir
    _PathProbe("app.py", False),
    _PathProbe("ignored.bin", False),
    _PathProbe("keep.bin", False),
    _PathProbe("build", True),
    _PathProbe("build/out.py", False),
    _PathProbe("pkg/build", True),
    _PathProbe("pkg/build/out.py", False),
    _PathProbe("pkg/.gitignore", False),
    _PathProbe("pkg/keep.bin", False),
    _PathProbe("pkg/noise.bin", False),
    _PathProbe("vendor", True),
    _PathProbe("vendor/keep.py", False),
    _PathProbe("anchored/build", True),
    _PathProbe("anchored/build/out.py", False),
    _PathProbe("docs/notes.md", False),
    _PathProbe("docs/temp/cache.txt", False),
    _PathProbe("a/temp/file.py", False),
    _PathProbe("b/deep/temp/file.py", False),
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
    for probe in _PATH_PROBES:
        target = corpus / probe.rel
        git_verdict = _is_git_ignored(corpus, target)
        matcher_verdict = matcher.is_ignored(target, is_dir=probe.is_dir)
        if git_verdict != matcher_verdict:
            disagreements.append(
                f"  {probe.rel} (is_dir={probe.is_dir}): "
                f"git={git_verdict} matcher={matcher_verdict}"
            )

    assert not disagreements, "GitignoreMatcher disagrees with git check-ignore:\n" + "\n".join(
        disagreements
    )
