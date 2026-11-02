"""Unit tests for ``GitignoreMatcher`` covering layered/nested gitignore rules."""

from pathlib import Path

import pytest

from gruffpy.source.gitignore import GitignoreMatcher


def _write(path: Path, text: str = "") -> None:
    """Write text to a file, creating any missing parent directories.

    Args:
        path: File to create or overwrite.
        text: UTF-8 content; empty by default.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_no_gitignore_means_nothing_ignored(tmp_path: Path) -> None:
    """Load no rules and ignore nothing when the root has no ``.gitignore``.

    Args:
        tmp_path: Root holding one module and no ignore file.
    """
    _write(tmp_path / "a.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert not matcher.has_rules()
    assert matcher.is_ignored(tmp_path / "a.py") is False


def test_root_gitignore_matches_file_at_root(tmp_path: Path) -> None:
    """Ignore the file a root ``.gitignore`` names while keeping an unnamed sibling.

    Args:
        tmp_path: Root whose ignore file names ``ignored.txt``, beside that file and a kept module.
    """
    _write(tmp_path / ".gitignore", "ignored.txt\n")
    _write(tmp_path / "ignored.txt")
    _write(tmp_path / "kept.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "ignored.txt") is True
    assert matcher.is_ignored(tmp_path / "kept.py") is False


def test_directory_pattern_requires_is_dir_flag(tmp_path: Path) -> None:
    """Ignore the folder a trailing-slash pattern names when it is checked as a directory, and the file inside it.

    Args:
        tmp_path: Root whose ignore file holds ``build/``, with one module inside ``build``.
    """
    _write(tmp_path / ".gitignore", "build/\n")
    (tmp_path / "build").mkdir()
    _write(tmp_path / "build" / "out.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "build", is_dir=True) is True
    assert matcher.is_ignored(tmp_path / "build" / "out.py") is True


def test_non_anchored_pattern_matches_at_any_depth(tmp_path: Path) -> None:
    """Match an unanchored folder pattern at any depth, ignoring a nested ``build`` folder and its file.

    Args:
        tmp_path: Root whose ignore file holds ``build/``, with that folder nested under ``pkg``.
    """
    _write(tmp_path / ".gitignore", "build/\n")
    (tmp_path / "pkg" / "build").mkdir(parents=True)
    _write(tmp_path / "pkg" / "build" / "out.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "pkg" / "build", is_dir=True) is True
    assert matcher.is_ignored(tmp_path / "pkg" / "build" / "out.py") is True


def test_anchored_pattern_matches_only_at_root(tmp_path: Path) -> None:
    """Match a leading-slash pattern only at the root, so the root ``build`` module is ignored and the nested one is not.

    Args:
        tmp_path: Root whose ignore file holds ``/build/``, with a module in both the root and the nested ``build`` folder.
    """
    _write(tmp_path / ".gitignore", "/build/\n")
    (tmp_path / "build").mkdir()
    (tmp_path / "pkg" / "build").mkdir(parents=True)
    _write(tmp_path / "build" / "out.py")
    _write(tmp_path / "pkg" / "build" / "out.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "build" / "out.py") is True
    assert matcher.is_ignored(tmp_path / "pkg" / "build" / "out.py") is False


def test_negation_pattern_re_includes(tmp_path: Path) -> None:
    """Re-include the file a later negation names after a glob ignored it.

    Args:
        tmp_path: Root whose ignore file ignores binaries and then re-includes ``keep.bin``.
    """
    _write(tmp_path / ".gitignore", "*.bin\n!keep.bin\n")
    _write(tmp_path / "ignored.bin")
    _write(tmp_path / "keep.bin")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "ignored.bin") is True
    assert matcher.is_ignored(tmp_path / "keep.bin") is False


def test_contents_glob_allows_later_file_reinclude(tmp_path: Path) -> None:
    """Let a later negation re-include one file under a contents glob, leaving its folder unignored and its sibling ignored.

    Args:
        tmp_path: Root whose ignore file ignores the contents of ``foo`` and then re-includes ``foo/bar.py``.
    """
    _write(tmp_path / ".gitignore", "/foo/**\n!foo/bar.py\n")
    _write(tmp_path / "foo" / "bar.py")
    _write(tmp_path / "foo" / "baz.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "foo", is_dir=True) is False
    assert matcher.is_ignored(tmp_path / "foo" / "bar.py") is False
    assert matcher.is_ignored(tmp_path / "foo" / "baz.py") is True


def test_symlink_matches_link_path_not_resolved_target(tmp_path: Path) -> None:
    """Match a symlink by its own path, not its target, so the link is kept while the target it points to is ignored.

    Skipped when the platform cannot create symlinks.

    Args:
        tmp_path: Root whose ignore file names ``target.py``, with a link to it named ``link.py``.
    """
    _write(tmp_path / ".gitignore", "target.py\n")
    _write(tmp_path / "target.py")
    link = tmp_path / "link.py"
    try:
        link.symlink_to(tmp_path / "target.py")
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(link) is False
    assert matcher.is_ignored(tmp_path / "target.py") is True


def test_nested_gitignore_overrides_root(tmp_path: Path) -> None:
    """Let a nested ``.gitignore`` negation re-include a file the root pattern ignores, while its sibling stays ignored.

    Args:
        tmp_path: Root that ignores binaries, with a ``pkg`` ignore file that re-includes ``keep.bin``.
    """
    _write(tmp_path / ".gitignore", "*.bin\n")
    _write(tmp_path / "pkg" / ".gitignore", "!keep.bin\n")
    _write(tmp_path / "pkg" / "noise.bin")
    _write(tmp_path / "pkg" / "keep.bin")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "pkg" / "noise.bin") is True
    assert matcher.is_ignored(tmp_path / "pkg" / "keep.bin") is False


def test_nested_gitignore_can_re_ignore_what_root_negated(tmp_path: Path) -> None:
    """Let a nested ``.gitignore`` ignore again a file the root negated, only inside that folder.

    Args:
        tmp_path: Root that ignores binaries except ``keep.bin``, with a ``pkg`` ignore file naming ``keep.bin``.
    """
    _write(tmp_path / ".gitignore", "*.bin\n!keep.bin\n")
    _write(tmp_path / "pkg" / ".gitignore", "keep.bin\n")
    _write(tmp_path / "keep.bin")
    _write(tmp_path / "pkg" / "keep.bin")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "keep.bin") is False
    assert matcher.is_ignored(tmp_path / "pkg" / "keep.bin") is True


def test_double_star_pattern(tmp_path: Path) -> None:
    """Match a double-star folder pattern at any depth while keeping a file outside those folders.

    Args:
        tmp_path: Root whose ignore file matches ``temp`` folders at any depth, with such folders at two depths.
    """
    _write(tmp_path / ".gitignore", "**/temp/\n")
    (tmp_path / "a" / "temp").mkdir(parents=True)
    (tmp_path / "b" / "deep" / "temp").mkdir(parents=True)
    _write(tmp_path / "a" / "temp" / "file.py")
    _write(tmp_path / "b" / "deep" / "temp" / "file.py")
    _write(tmp_path / "a" / "kept.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "a" / "temp" / "file.py") is True
    assert matcher.is_ignored(tmp_path / "b" / "deep" / "temp" / "file.py") is True
    assert matcher.is_ignored(tmp_path / "a" / "kept.py") is False


def test_path_outside_root_is_not_ignored(tmp_path: Path) -> None:
    """Ignore nothing outside the matcher's root, even when a root pattern would match it.

    Args:
        tmp_path: Parent folder holding the ``project`` root, which ignores binaries, and a binary beside that root.
    """
    _write(tmp_path / "project" / ".gitignore", "*.bin\n")
    _write(tmp_path / "project" / "ignored.bin")
    _write(tmp_path / "sibling.bin")

    matcher = GitignoreMatcher.from_root(tmp_path / "project")

    assert matcher.is_ignored(tmp_path / "project" / "ignored.bin") is True
    assert matcher.is_ignored(tmp_path / "sibling.bin") is False


def test_comment_and_blank_lines_are_tolerated(tmp_path: Path) -> None:
    """Skip comment and blank lines in a ``.gitignore`` while applying the pattern between them.

    Args:
        tmp_path: Root whose ignore file surrounds one binary pattern with comments and blank lines.
    """
    _write(
        tmp_path / ".gitignore",
        "# leading comment\n\n*.bin\n   \n# trailing comment\n",
    )
    _write(tmp_path / "x.bin")
    _write(tmp_path / "y.py")

    matcher = GitignoreMatcher.from_root(tmp_path)

    assert matcher.is_ignored(tmp_path / "x.bin") is True
    assert matcher.is_ignored(tmp_path / "y.py") is False


def test_has_rules_reflects_loaded_state(tmp_path: Path) -> None:
    """Report loaded rules only after a ``.gitignore`` appears in the root.

    Args:
        tmp_path: Root checked before and after its ignore file is written.
    """
    assert GitignoreMatcher.from_root(tmp_path).has_rules() is False

    _write(tmp_path / ".gitignore", "ignored.txt\n")
    assert GitignoreMatcher.from_root(tmp_path).has_rules() is True
