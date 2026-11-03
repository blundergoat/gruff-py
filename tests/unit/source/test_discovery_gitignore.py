"""Tests for ``SourceDiscovery`` honoring ``.gitignore`` alongside its other layers."""

from pathlib import Path

from gruffpy.source.discovery import SourceDiscovery


def _write(path: Path, text: str = "") -> None:
    """Write text to a file, creating any missing parent directories.

    Args:
        path: File to create or overwrite.
        text: UTF-8 content; empty by default.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _display_paths(result_files: tuple) -> set[str]:
    """Collect the display paths of discovered source files.

    Args:
        result_files: Source files from a discovery result.

    Returns:
        The distinct display paths.
    """
    return {sf.display_path for sf in result_files}


def test_no_gitignore_means_discovery_unchanged(tmp_path: Path) -> None:
    """Discover an ordinary module when the project has no ``.gitignore``.

    Args:
        tmp_path: Project root holding only ``src/app.py``.
    """
    _write(tmp_path / "src" / "app.py", "x = 1\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert "src/app.py" in _display_paths(result.files)


def test_gitignored_file_is_excluded_from_discovery(tmp_path: Path) -> None:
    """Leave the file a root ``.gitignore`` names out of discovery while finding its unignored sibling.

    Args:
        tmp_path: Project root whose ignore file names ``src/secret.py``, beside ``src/app.py``.
    """
    _write(tmp_path / ".gitignore", "src/secret.py\n")
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "src" / "secret.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files)
    assert "src/app.py" in paths
    assert "src/secret.py" not in paths


def test_gitignored_directory_is_reported_in_ignored_paths(tmp_path: Path) -> None:
    """Skip a gitignored folder's files and list the folder among the ignored paths.

    Args:
        tmp_path: Project root whose ignore file holds ``build/``, with one module in ``build`` and one in ``src``.
    """
    _write(tmp_path / ".gitignore", "build/\n")
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "build" / "out.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files)
    assert "src/app.py" in paths
    assert "build/out.py" not in paths
    assert "build" in result.ignored_paths


def test_include_ignored_bypasses_gitignore(tmp_path: Path) -> None:
    """Discover files in a gitignored folder when ``include_ignored`` is set.

    Args:
        tmp_path: Project root whose ignore file holds ``build/``, with modules in ``build`` and ``src``.
    """
    _write(tmp_path / ".gitignore", "build/\n")
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "build" / "out.py")

    result = SourceDiscovery(tmp_path).discover(["."], include_ignored=True)

    paths = _display_paths(result.files)
    assert "src/app.py" in paths
    assert "build/out.py" in paths


def test_configured_patterns_apply_even_with_include_ignored(tmp_path: Path) -> None:
    """Keep configured ignore patterns in force under ``include_ignored``, so a fixture module stays undiscovered.

    Args:
        tmp_path: Project root holding an application module and a module under ``tests/fixtures``.
    """
    _write(tmp_path / "src" / "app.py")
    _write(tmp_path / "tests" / "fixtures" / "fixture.py")

    result = SourceDiscovery(tmp_path).discover(
        ["."],
        include_ignored=True,
        configured_ignore_patterns=["tests/fixtures/**"],
    )

    paths = _display_paths(result.files)
    assert "src/app.py" in paths
    assert "tests/fixtures/fixture.py" not in paths


def test_nested_gitignore_negation_re_includes_file(tmp_path: Path) -> None:
    """Discover a file a nested ``.gitignore`` re-includes while its root-ignored sibling stays out.

    Args:
        tmp_path: Project root that ignores generated modules, with a ``pkg`` ignore file that re-includes one.
    """
    _write(tmp_path / ".gitignore", "*.gen.py\n")
    _write(tmp_path / "pkg" / ".gitignore", "!keep.gen.py\n")
    _write(tmp_path / "pkg" / "ignored.gen.py")
    _write(tmp_path / "pkg" / "keep.gen.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files)
    assert "pkg/keep.gen.py" in paths
    assert "pkg/ignored.gen.py" not in paths


def test_gitignore_contents_glob_reincluded_child_is_discovered(tmp_path: Path) -> None:
    """Discover a child a later negation re-includes under a contents glob, while its sibling stays out.

    Args:
        tmp_path: Project root whose ignore file ignores the contents of ``foo`` and then re-includes ``foo/bar.py``.
    """
    _write(tmp_path / ".gitignore", "/foo/**\n!foo/bar.py\n")
    _write(tmp_path / "foo" / "bar.py")
    _write(tmp_path / "foo" / "baz.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files)
    assert "foo/bar.py" in paths
    assert "foo/baz.py" not in paths


def test_explicit_gitignored_path_is_scanned(tmp_path: Path) -> None:
    """Discover a gitignored file when it is named explicitly as an operand.

    Args:
        tmp_path: Project root whose ignore file names ``secret.py``, beside that file.
    """
    _write(tmp_path / ".gitignore", "secret.py\n")
    _write(tmp_path / "secret.py")

    default = SourceDiscovery(tmp_path).discover(["secret.py"])
    assert "secret.py" in _display_paths(default.files)


def test_ancestor_gitignore_disables_non_vcs_fallback_for_its_subtree(tmp_path: Path) -> None:
    """Discover ``node_modules`` files under a package with its own ``.gitignore``, while another package's ``node_modules`` stays skipped.

    Args:
        tmp_path: Project root holding two packages with a ``node_modules`` module each; only one package has an ignore file.
    """
    # node_modules defers to a governing .gitignore; vendor and dist never do (section 7, precision-floor M04).
    _write(tmp_path / "packages" / "app" / ".gitignore", "*.log\n")
    _write(tmp_path / "packages" / "app" / "node_modules" / "visible.py")
    _write(tmp_path / "packages" / "other" / "node_modules" / "hidden.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files)
    assert "packages/app/node_modules/visible.py" in paths
    assert "packages/other/node_modules/hidden.py" not in paths


def test_gitignored_directory_descent_is_skipped(tmp_path: Path) -> None:
    """Gitignored directories must not be walked into (performance + correctness).

    Args:
        tmp_path: Pytest-provided per-test directory holding the synthetic project tree.
    """
    _write(tmp_path / ".gitignore", "vendor/\n")
    _write(tmp_path / "vendor" / "a.py")
    _write(tmp_path / "vendor" / "deep" / "b.py")
    _write(tmp_path / "src" / "app.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    paths = _display_paths(result.files)
    assert "src/app.py" in paths
    assert not any(p.startswith("vendor/") for p in paths)


def test_gitignored_paths_only_directories_appear_in_ignored_summary(tmp_path: Path) -> None:
    """Match the existing convention: files are silently skipped; directories are summarised.

    Args:
        tmp_path: Pytest-provided per-test directory holding the synthetic project tree.
    """
    _write(tmp_path / ".gitignore", "skip_me.py\nvendor/\n")
    _write(tmp_path / "skip_me.py")
    _write(tmp_path / "vendor" / "lib.py")
    _write(tmp_path / "kept.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert "skip_me.py" not in result.ignored_paths
    assert "vendor" in result.ignored_paths
