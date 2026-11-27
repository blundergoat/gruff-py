"""Tests for ignore-reason reporting and the shared ``SourceDiscovery.classify`` engine."""

from pathlib import Path

from gruffpy.source.discovery import IgnoredPath, SourceDiscovery


def _write(path: Path, text: str = "") -> None:
    """Write text to a file, creating any missing parent directories.

    Args:
        path: File to create or overwrite.
        text: Content to encode as UTF-8. An omitted or empty value creates an empty file or clears an existing one.

    Returns:
        None. Creates missing parent directories and writes the file as UTF-8.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_hidden_sources(parent: Path, directory_names: tuple[str, ...]) -> None:
    """Place one Python file inside each named directory, so discovery has something to skip.

    Args:
        parent: Directory the named directories are created under.
        directory_names: Directory names the fallback policy is expected to ignore.

    Returns:
        None. Writes an empty hidden.py in each named directory.
    """
    for name in directory_names:
        _write(parent / name / "hidden.py")


def test_classify_reports_config_source_and_matched_pattern(tmp_path: Path) -> None:
    """Classify a config-ignored path with the config source and the matching pattern.

    Args:
        tmp_path: Project root holding gen/out.py, which the config pattern matches.

    Returns:
        None. Asserts the config ignore record for gen/out.py, including the matched glob.
    """
    _write(tmp_path / "gen" / "out.py")

    result = SourceDiscovery(tmp_path).classify("gen/out.py", configured_ignore_patterns=["gen/**"])

    assert result == IgnoredPath(path="gen/out.py", source="config", pattern="gen/**")


def test_classify_config_match_wins_even_with_include_ignored(tmp_path: Path) -> None:
    """Keep a config match as the ignore reason even when ignored paths are included.

    Args:
        tmp_path: Project root holding gen/out.py, which the config pattern matches.

    Returns:
        None. Asserts that the config ignore reason survives include_ignored=True.
    """
    _write(tmp_path / "gen" / "out.py")

    result = SourceDiscovery(tmp_path).classify("gen/out.py", include_ignored=True, configured_ignore_patterns=["gen/**"])

    assert result is not None
    assert result.source == "config"


def test_classify_reports_default_directory_source(tmp_path: Path) -> None:
    """Classify node_modules as ignored by the built-in default directory list.

    Args:
        tmp_path: Project root holding an empty node_modules folder.

    Returns:
        None. Asserts that node_modules is reported with the matching default directory name.
    """
    (tmp_path / "node_modules").mkdir()

    result = SourceDiscovery(tmp_path).classify("node_modules")

    assert result == IgnoredPath(path="node_modules", source="default", pattern="node_modules")


def test_classify_existing_file_uses_explicit_semantics(tmp_path: Path) -> None:
    """Report no ignore reason for an existing file named directly, even though .gitignore lists it.

    Args:
        tmp_path: Project root whose ignore file names secret.py, beside that file.

    Returns:
        None. Asserts that naming the existing secret.py directly yields no ignore reason.
    """
    _write(tmp_path / ".gitignore", "secret.py\n")
    _write(tmp_path / "secret.py")

    result = SourceDiscovery(tmp_path).classify("secret.py")

    assert result is None


def test_classify_does_not_ignore_lockfile_by_filename(tmp_path: Path) -> None:
    """Report no ignore reason for uv.lock from its filename alone.

    Args:
        tmp_path: Empty project root; the lockfile is never written.

    Returns:
        None. Asserts that classifying the unwritten uv.lock yields no ignore reason.
    """
    result = SourceDiscovery(tmp_path).classify("uv.lock")

    assert result is None


def test_classify_returns_none_for_non_ignored_path(tmp_path: Path) -> None:
    """Report no ignore reason for an ordinary source path.

    Args:
        tmp_path: Empty project root the path is classified against.

    Returns:
        None. Asserts that src/app.py has no ignore reason in the empty project.
    """
    assert SourceDiscovery(tmp_path).classify("src/app.py") is None


def test_classify_works_on_hypothetical_path_not_on_disk(tmp_path: Path) -> None:
    """Classify a path that does not exist on disk by the config pattern it would match.

    Args:
        tmp_path: Empty project root; the classified file is never written.

    Returns:
        None. Asserts that the unwritten gen/missing.py has a config ignore reason.
    """
    result = SourceDiscovery(tmp_path).classify("gen/missing.py", configured_ignore_patterns=["gen/**"])

    assert result is not None
    assert result.source == "config"


def test_discover_records_ignore_reason_for_explicit_config_match(tmp_path: Path) -> None:
    """Discover nothing for an explicitly named config-ignored file, and record it with its config reason.

    Args:
        tmp_path: Project root holding gen/out.py, which the config pattern matches.

    Returns:
        None. Asserts that discovery excludes gen/out.py and records its path and config reason.
    """
    _write(tmp_path / "gen" / "out.py")

    result = SourceDiscovery(tmp_path).discover(["gen/out.py"], configured_ignore_patterns=["gen/**"])

    assert result.files == ()
    assert result.ignored_paths == ("gen/out.py",)
    assert result.ignored_path_reasons == (IgnoredPath(path="gen/out.py", source="config", pattern="gen/**"),)


def test_explicit_ineligible_lockfile_is_not_reported_as_ignored(tmp_path: Path) -> None:
    """Discover nothing for an explicitly named uv.lock, and record no ignore reason for it.

    Args:
        tmp_path: Project root holding a uv.lock file.

    Returns:
        None. Asserts that explicitly naming uv.lock yields no source file or ignore reason.
    """
    _write(tmp_path / "uv.lock", "# lock\n")

    result = SourceDiscovery(tmp_path).discover(["uv.lock"])

    assert result.files == ()
    assert result.ignored_path_reasons == ()


def test_walk_treats_ineligible_lockfile_as_unsupported_not_ignored(tmp_path: Path) -> None:
    """Skip uv.lock during a directory walk without recording it as ignored, while the module beside it is discovered.

    Args:
        tmp_path: Project root holding uv.lock and app.py.

    Returns:
        None. Asserts that the walk finds only app.py and produces no ignore reasons.
    """
    _write(tmp_path / "uv.lock", "# lock\n")
    _write(tmp_path / "app.py", "x = 1\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert [source.display_path for source in result.files] == ["app.py"]
    assert result.ignored_path_reasons == ()


def test_eligible_json_lockfile_is_scanned(tmp_path: Path) -> None:
    """Discover a package-lock.json file during a directory walk.

    Args:
        tmp_path: Project root holding a JSON lockfile containing an empty object.

    Returns:
        None. Asserts that the walk discovers package-lock.json as its sole file.
    """
    _write(tmp_path / "package-lock.json", "{}\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert [source.display_path for source in result.files] == ["package-lock.json"]


def test_vcs_internals_remain_blocked_for_explicit_file_and_include_ignored(
    tmp_path: Path,
) -> None:
    """Keep a file under .git out of discovery when named explicitly with ignored paths included, with the default .git reason.

    Args:
        tmp_path: Project root holding a Python file inside .git.

    Returns:
        None. Asserts that .git/config.py is excluded with the default .git reason despite both inclusion options.
    """
    _write(tmp_path / ".git" / "config.py")

    result = SourceDiscovery(tmp_path).discover([".git/config.py"], include_ignored=True)

    assert result.files == ()
    assert result.ignored_path_reasons == (IgnoredPath(path=".git/config.py", source="default", pattern=".git"),)


def test_python_fallback_exceptions_apply_at_any_depth(tmp_path: Path) -> None:
    """Skip nested Python tool and cache folders, reporting each by name, while cache, generated and .goat-flow stay in scope.

    Args:
        tmp_path: Project root holding one module in each skipped folder under nested and in the three folders that stay.

    Returns:
        None. Asserts the fallback reason names and the discovered files under cache, generated and .goat-flow.
    """
    ignored_names = (
        ".mypy_cache",
        ".pyre",
        ".pytest_cache",
        ".pytype",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "htmlcov",
        "venv",
    )
    _write_hidden_sources(tmp_path / "nested", ignored_names)
    _write(tmp_path / "cache" / "visible.py")
    _write(tmp_path / "generated" / "visible.py")
    _write(tmp_path / ".goat-flow" / "visible.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {
        ".goat-flow/visible.py",
        "cache/visible.py",
        "generated/visible.py",
    }
    assert {reason.pattern for reason in result.ignored_path_reasons} == set(ignored_names)


def test_discover_ignored_paths_remains_plain_strings(tmp_path: Path) -> None:
    """Keep the discovery result's ignored paths as plain strings that include the config-ignored module.

    Args:
        tmp_path: Project root holding a config-ignored module under gen and an ordinary one under src.

    Returns:
        None. Asserts that ignored_paths contains gen/out.py and consists of strings.
    """
    _write(tmp_path / "gen" / "out.py")
    _write(tmp_path / "src" / "app.py")

    result = SourceDiscovery(tmp_path).discover(["."], configured_ignore_patterns=["gen/**"])

    assert all(isinstance(path, str) for path in result.ignored_paths)
    assert "gen/out.py" in result.ignored_paths


def test_third_party_directories_are_skipped_under_a_governing_gitignore(tmp_path: Path) -> None:
    """Skip copied and built modules under the tested directory names even when a .gitignore governs them.

    Args:
        tmp_path: Synthetic project root.

    Returns:
        None. Asserts the default directory exclusions and verifies that only src/app.py is discovered.
    """
    _write(tmp_path / ".gitignore", "*.log\n")
    for directory in ("vendor", "Vendors", "pkg/THIRD_PARTY", "pkg/third-party", "web/bower_components", "app/Dist"):
        _write(tmp_path / directory / "copied.py")
    _write(tmp_path / "src" / "app.py")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {"src/app.py"}
    assert {(reason.path, reason.source, reason.pattern) for reason in result.ignored_path_reasons} == {
        ("vendor", "default", "vendor"),
        ("Vendors", "default", "vendors"),
        ("pkg/THIRD_PARTY", "default", "third_party"),
        ("pkg/third-party", "default", "third-party"),
        ("web/bower_components", "default", "bower_components"),
        ("app/Dist", "default", "dist"),
    }


def test_outermost_third_party_directory_names_the_reason(tmp_path: Path) -> None:
    """Classify a missing sibling under nested third-party folders by the outermost vendor, while the existing file named directly gets no reason.

    Args:
        tmp_path: Project root holding one module nested under vendor/lib/dist.

    Returns:
        None. Asserts no ignore reason for the existing file and the outermost vendor reason for its missing sibling.
    """
    _write(tmp_path / "vendor" / "lib" / "dist" / "copied.py")

    result = SourceDiscovery(tmp_path).classify("vendor/lib/dist/copied.py", include_ignored=False)

    # Naming an existing file directly bypasses third-party directory exclusions, so the missing sibling shows which directory wins.
    assert result is None
    assert SourceDiscovery(tmp_path).classify("vendor/lib/dist/other.py") == IgnoredPath(
        path="vendor/lib/dist/other.py", source="default", pattern="vendor"
    )


def test_minified_files_are_skipped_and_listed_only_when_eligible(tmp_path: Path) -> None:
    """Skip minified files and list only the minified JSON one as ignored, while the plain JSON file is discovered.

    Args:
        tmp_path: Project root holding a minified JSON file, a minified script and a plain JSON file.

    Returns:
        None. Asserts that the walk discovers the plain JSON file and records only the minified JSON file as ignored.
    """
    _write(tmp_path / "config" / "settings.min.json", "{}")
    _write(tmp_path / "static" / "jquery.min.js", "var a=1;")
    _write(tmp_path / "config" / "settings.json", "{}")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {"config/settings.json"}
    # jquery.min.js has no supported source type, so discovery leaves it out of the ignore report.
    assert result.ignored_path_reasons == (IgnoredPath(path="config/settings.min.json", source="default", pattern="*.min.*"),)


def test_include_ignored_and_explicit_files_bring_the_classes_back(tmp_path: Path) -> None:
    """Discover third-party, build-output and minified files under include_ignored, and the named ones when listed explicitly.

    Args:
        tmp_path: Project root holding one file in vendor, one in dist and a minified JSON file.

    Returns:
        None. Asserts that include_ignored restores all three files and explicit discovery returns the two named files.
    """
    _write(tmp_path / "vendor" / "copied.py")
    _write(tmp_path / "dist" / "built.py")
    _write(tmp_path / "config" / "settings.min.json", "{}")

    included = SourceDiscovery(tmp_path).discover(["."], include_ignored=True)
    explicit = SourceDiscovery(tmp_path).discover(["vendor/copied.py", "config/settings.min.json"])

    assert {source.display_path for source in included.files} == {"vendor/copied.py", "dist/built.py", "config/settings.min.json"}
    assert {source.display_path for source in explicit.files} == {"vendor/copied.py", "config/settings.min.json"}


def test_first_party_names_that_only_resemble_the_classes_stay_in_scope(tmp_path: Path) -> None:
    """Discover first-party files whose names only resemble the third-party, build-output or minified classes.

    Args:
        tmp_path: Project root holding look-alike modules and a .gitignore that ignores only logs.

    Returns:
        None. Asserts that discovery keeps every look-alike path in the fixture.
    """
    for relative in (
        "src/vendor_api.py",
        "src/vendors.py",
        "src/dist.py",
        "build/scripts/release.py",
        "lib/helpers.py",
        "external/typings.py",
        "src/admin.mini.py",
        "src/min.py",
    ):
        _write(tmp_path / relative)
    _write(tmp_path / ".gitignore", "*.log\n")

    result = SourceDiscovery(tmp_path).discover(["."])

    assert {source.display_path for source in result.files} == {
        "src/vendor_api.py",
        "src/vendors.py",
        "src/dist.py",
        "build/scripts/release.py",
        "lib/helpers.py",
        "external/typings.py",
        "src/admin.mini.py",
        "src/min.py",
    }


def test_ignored_external_symlink_does_not_fail_containment(tmp_path: Path) -> None:
    """Honor .gitignore and paths.ignore on symlinks before checking external-target containment.

    Args:
        tmp_path: Temporary directory holding both the project root and an outside target file.

    Returns:
        None. Checks that ignored external symlinks stay out of outside_paths while non-ignored ones still trigger containment.
    """
    project = tmp_path / "project"
    outside = tmp_path / "outside.py"
    _write(outside, "value = 1\n")
    _write(project / ".gitignore", "ignored_git_link.py\n")
    _write(project / "src" / "app.py", "value = 2\n")
    (project / "ignored_git_link.py").symlink_to(outside)
    (project / "ignored_config_link.py").symlink_to(outside)

    ignored_run = SourceDiscovery(project).discover(["."], configured_ignore_patterns=["ignored_config_link.py"])

    assert [source.display_path for source in ignored_run.files] == ["src/app.py"]
    assert ignored_run.outside_paths == ()
    assert ignored_run.ignored_paths == ("ignored_config_link.py",)

    (project / "live_external_link.py").symlink_to(outside)
    escaping_run = SourceDiscovery(project).discover(["."], configured_ignore_patterns=["ignored_config_link.py"])

    assert escaping_run.outside_paths == ("live_external_link.py",)


def test_in_project_symlink_into_an_ignored_folder_stays_skipped(tmp_path: Path) -> None:
    """Judge an in-project link by its target too, so a link into a paths.ignore folder is not analysed.

    Args:
        tmp_path: Temporary project root holding the ignored target folder and the link.

    Returns:
        None. Checks that the link is skipped and reported under its own path.
    """
    _write(tmp_path / "generated" / "model.py", "value = 1\n")
    _write(tmp_path / "src" / "app.py", "value = 2\n")
    (tmp_path / "src" / "model.py").symlink_to(tmp_path / "generated" / "model.py")

    run = SourceDiscovery(tmp_path).discover(["src"], configured_ignore_patterns=["generated/**"])

    assert [source.display_path for source in run.files] == ["src/app.py"]
    assert run.ignored_paths == ("src/model.py",)


def test_in_project_symlink_into_a_gitignored_folder_stays_skipped(tmp_path: Path) -> None:
    """Judge an in-project link by its target against .gitignore too, so a link into a gitignored folder is not analysed.

    Args:
        tmp_path: Temporary project root holding the .gitignore rule, target folder, and link.

    Returns:
        None. Checks that only the non-ignored module is discovered and the symlinked gitignored target is skipped.
    """
    _write(tmp_path / ".gitignore", "generated/\n")
    _write(tmp_path / "generated" / "model.py", "value = 1\n")
    _write(tmp_path / "src" / "app.py", "value = 2\n")
    (tmp_path / "src" / "model.py").symlink_to(tmp_path / "generated" / "model.py")

    run = SourceDiscovery(tmp_path).discover(["src"])

    assert [source.display_path for source in run.files] == ["src/app.py"]
    assert run.outside_paths == ()
