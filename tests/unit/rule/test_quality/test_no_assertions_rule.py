from dataclasses import replace
from pathlib import Path

import pytest

from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.test_quality.no_assertions_rule import NoAssertionsRule
from gruffpy.source.source_file import SourceFile
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_no_assert_emits():
    """Report one finding for a test whose body only assigns a local.

    Returns:
        None. Checks that the rule emits one finding for a test consisting only of a local assignment.
    """
    src = "def test_foo():\n    x = 1\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_collected_test_without_assertions_still_emits():
    """Report one finding for a test that only calls the system and asserts nothing.

    Returns:
        None. Checks that calling exercise_system without an assertion still yields one finding.
    """
    src = "def test_missing_assertion():\n    exercise_system()\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_skipped():
    """Report nothing for a test with a plain assert.

    Returns:
        None. Checks that a plain assert is sufficient for the rule to return no findings.
    """
    src = "def test_foo():\n    assert 1 + 1 == 2\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_unittest_assert_method_counts_as_assertion() -> None:
    """Recognise unittest assertion methods as test verification.

    Returns:
        None. Checks that the rule returns no findings for the TestX method containing self.assertEqual.
    """
    src = "class TestX:\n    def test_a(self):\n        self.assertEqual(1, 1)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    ("base", "expected_count"),
    [
        ("unittest.TestCase", 1),
        ("IsolatedAsyncioTestCase", 1),
        ("unittest.IsolatedAsyncioTestCase", 1),
        ("ut.IsolatedAsyncioTestCase", 1),
        ("OrdinaryClass", 0),
    ],
)
def test_async_unittest_base_recognition(base: str, expected_count: int) -> None:
    """Report an assertion-free unittest method for supported base spellings.

    Args:
        base: Bare or qualified base expression on the test class.
        expected_count: Expected findings, with ordinary classes excluded.

    Returns:
        None. Checks for one finding with each supported unittest base spelling and zero for the OrdinaryClass fixture.
    """
    source = f"class AsyncChecks({base}):\n    async def testRuns(self):\n        pass\n"
    findings = NoAssertionsRule().analyse(make_unit(source), default_ctx())
    assert len(findings) == expected_count


def test_pytest_raises_block_counts_as_assertion() -> None:
    """Recognise the canonical pytest exception context manager.

    Returns:
        None. Checks that the pytest.raises context produces no findings.
    """
    src = "import pytest\ndef test_foo():\n    with pytest.raises(ValueError):\n        raise ValueError\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_parametrized_pytest_raises_context_counts_as_assertion() -> None:
    """Recognise a verification context constructed by parametrisation.

    Returns:
        None. Checks for no findings when parametrisation supplies the exception context.
    """
    src = (
        "import pytest\n"
        '@pytest.mark.parametrize("exception", [pytest.raises(ValueError)])\n'
        "def test_foo(exception):\n"
        "    with exception:\n"
        "        raise ValueError\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "source",
    [
        "from pytest import raises\ndef test_value():\n    with raises(ValueError):\n        int('not-an-integer')\n",
        "from pytest import raises as expect_error\ndef test_value():\n    with expect_error(ValueError):\n        int('not-an-integer')\n",
        "import pytest as test_framework\ndef test_value():\n    with test_framework.raises(ValueError):\n        int('not-an-integer')\n",
    ],
    ids=["direct-helper", "renamed-helper", "renamed-module"],
)
def test_imported_pytest_raises_counts_as_assertion(source: str) -> None:
    """Recognise pytest.raises when imported directly, imported under a different name, or called through a module alias.

    Args:
        source: Test source using a direct, renamed, or module-aliased pytest helper.

    Returns:
        None. Checks that the supplied import form produces no findings.
    """
    assert NoAssertionsRule().analyse(make_unit(source), default_ctx()) == []


def test_pytest_warns_block_counts_as_assertion() -> None:
    """Recognise the canonical pytest warning context manager.

    Returns:
        None. Checks that the pytest.warns context produces no findings.
    """
    src = "import pytest\ndef test_value():\n    with pytest.warns(UserWarning):\n        warn_user()\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_pytest_fail_counts_as_assertion():
    """Report nothing for a test whose only check is pytest.fail.

    Returns:
        None. Checks for no findings when pytest.fail is the only call.
    """
    src = "import pytest\ndef test_foo():\n    pytest.fail('bad branch')\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_warnings_catch_warnings_counts_as_assertion():
    """Report nothing for a test that turns RuntimeWarning into an error inside warnings.catch_warnings.

    Returns:
        None. Checks for no findings when the test turns RuntimeWarning into an error.
    """
    src = (
        "import warnings\n"
        "def test_foo():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', RuntimeWarning)\n"
        "        run_without_warning()\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_warnings_filterwarnings_error_counts_as_assertion():
    """Report nothing for a test that turns every warning into an error inside warnings.catch_warnings.

    Returns:
        None. Checks for no findings when the warning filter turns all warnings into errors.
    """
    src = (
        "import warnings\n"
        "def test_foo():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.filterwarnings('error')\n"
        "        run_without_warning()\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_bare_catch_warnings_without_error_filter_emits():
    """Report one finding for a test that opens warnings.catch_warnings without an error filter.

    Returns:
        None. Checks for one finding when the warning context has no error filter.
    """
    src = "import warnings\ndef test_foo():\n    with warnings.catch_warnings():\n        do_work()\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_catch_warnings_with_ignore_filter_emits():
    """Report one finding for a test that only ignores warnings inside warnings.catch_warnings.

    Returns:
        None. Checks that ignoring warnings still produces one finding.
    """
    src = "import warnings\ndef test_foo():\n    with warnings.catch_warnings():\n        warnings.simplefilter('ignore')\n        do_work()\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_bare_assert_helper_counts_as_assertion():
    """Report nothing for a test whose only call is an assert_-prefixed helper.

    Returns:
        None. Checks for no findings when the test calls an assert_-prefixed helper directly.
    """
    src = "def test_image():\n    assert_image_mostly_same(actual, expected)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_dotted_assert_helper_counts_as_assertion():
    """Report nothing for a test whose only call is to an assert_-prefixed attribute.

    Returns:
        None. Checks that the dotted assertion-helper call produces no findings.
    """
    src = "def test_image():\n    helpers.assert_image_mostly_same(actual, expected)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_non_assert_helper_does_not_count():
    """Report one finding for a test whose only call is a helper without the assert_ prefix.

    Returns:
        None. Checks for one finding when the test only calls compare_image.
    """
    src = "def test_image():\n    compare_image(actual, expected)\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("_assert_turn(route(turn), 'local')", 0),
        ("monkeypatch.setattr(service, 'write_event', fail_write)\n    service.answer()", 0),
        ("with patch.object(service, 'write_event', new=fail_write):\n        service.answer()", 0),
        ("with mock.patch.object(service, 'write_event', new=fail_write):\n        service.answer()", 0),
        ("with unittest.mock.patch('pkg.write_event', side_effect=fail_write):\n        service.answer()", 0),
        ("with unittest.mock.patch.object(service, 'write_event', fail_write):\n        service.answer()", 0),
        ("service.answer()", 1),
        ("monkeypatch.setattr(fail_write, 'sentinel', service.answer)", 1),
    ],
    ids=[
        "private-assertion",
        "installed-failure-fake",
        "patched-failure-fake",
        "mock-patch-object-failure-fake",
        "unittest-mock-patch-failure-fake",
        "unittest-mock-patch-object-failure-fake",
        "uninstalled-fake",
        "fake-is-patch-target",
    ],
)
def test_assertion_helpers_and_installed_raising_fakes(body: str, expected: int) -> None:
    """Recognise assertion helpers and installed failure fakes while reporting tests without recognised verification.

    Args:
        body: Source snippet inserted after the local fail_write definition to exercise the current case.
        expected: Number of no-assertions findings.

    Returns:
        None. Checks that the snippet produces the expected number of findings.
    """
    source = (
        "def test_production_mode(monkeypatch):\n"
        "    def fail_write(*args, **kwargs):\n"
        "        raise AssertionError('tester write must not run')\n"
        f"    {body}\n"
    )
    assert len(NoAssertionsRule().analyse(make_unit(source), default_ctx())) == expected


def test_fixture_named_test_image_is_not_reported():
    """Report nothing for a pytest.fixture function whose name starts with test_.

    Returns:
        None. Checks that the pytest fixture produces no findings despite its test_ name.
    """
    src = "import pytest\n@pytest.fixture\ndef test_image():\n    return load_image()\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_called_fixture_named_test_image_is_not_reported():
    """Report nothing for a test_-named function decorated with a called fixture().

    Returns:
        None. Checks for no findings when a test_-named function uses the fixture() decorator.
    """
    src = "from pytest import fixture\n@fixture()\ndef test_image():\n    return load_image()\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_conftest_fixture_factory_is_not_reported():
    """Report nothing for a fixture factory in conftest.py.

    Returns:
        None. Checks that the conftest.py fixture factory produces no findings.
    """
    src = "import pytest\n@pytest.fixture\ndef image_factory():\n    return ImageFactory()\n"
    assert NoAssertionsRule().analyse(make_unit(src, "tests/conftest.py"), default_ctx()) == []


def test_conftest_plain_support_function_is_not_reported():
    """Report nothing for a plain support function in conftest.py.

    Returns:
        None. Checks that the undecorated helper in conftest.py produces no findings.
    """
    src = "def build_image():\n    return ImageFactory()\n"
    assert NoAssertionsRule().analyse(make_unit(src, "tests/conftest.py"), default_ctx()) == []


def test_non_test_function_skipped():
    """Report nothing for a helper whose name does not start with test_.

    Returns:
        None. Checks for no findings on a helper without the test_ prefix.
    """
    src = "def helper():\n    x = 1\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def _unit_under(project_root: Path, display_path: str, source: str) -> tuple[AnalysisUnit, RuleContext]:
    """Place a parsed unit at display_path beneath a real project root.

    Args:
        project_root: Temporary project directory where the rule checks for package initializers and looks up pytest settings.
        display_path: Project-relative path of the analysed file.
        source: Python source to parse.

    Returns:
        The unit and a default-configured context rooted at project_root.
    """
    unit = make_unit(source, display_path)
    located = SourceFile(absolute_path=str(project_root / display_path), display_path=display_path, type="python")
    return replace(unit, file=located), RuleContext(project_root=str(project_root), config=default_ctx().config)


@pytest.mark.parametrize(
    "display_path",
    [
        "django/test/runner.py",
        "examples/mark_safe_insecure.py",
        "examples/performance/bulk_inserts.py",
        "noxfile.py",
    ],
    ids=["shipped-runner-module", "analyser-fixture-corpus", "benchmark-harness", "noxfile"],
)
def test_test_named_function_in_a_file_no_runner_collects_reports_nothing(display_path: str) -> None:
    """Skip test-named functions in the supplied paths outside default pytest and unittest discovery.

    Args:
        display_path: Project-relative path pytest and unittest discovery both ignore.

    Returns:
        None. Checks that the test-named function produces no findings at the supplied path.
    """
    src = "def test_shape(record):\n    return record\n"
    assert NoAssertionsRule().analyse(make_unit(src, display_path), default_ctx()) == []


@pytest.mark.parametrize(
    "display_path", ["test_guard.py", "tests/test_api.py", "src/app/api_test.py"], ids=["root-test-module", "tests-directory", "suffix-module"]
)
def test_collected_file_still_reports(display_path: str) -> None:
    """Expect one finding for an assertion-free test at each supplied path matching pytest's default file globs.

    Args:
        display_path: Project-relative path matching pytest's default python_files globs.

    Returns:
        None. Checks for one finding with remediation that includes "delete the test".
    """
    src = "def test_without_assertion() -> int:\n    value = 1\n    return value\n"
    findings = NoAssertionsRule().analyse(make_unit(src, display_path), default_ctx())
    assert len(findings) == 1
    assert "delete the test" in (findings[0].remediation or "")


def test_unittest_discovery_file_reports_testcase_methods_only() -> None:
    """Report TestCase methods in a unittest-discovered tests.py but not bare functions there.

    Returns:
        None. Checks for one finding on the TestCase method and none on the bare function.
    """
    method_src = "import unittest\nclass ViewTests(unittest.TestCase):\n    def test_view(self):\n        self.client.get('/')\n"
    bare_src = "def test_view(client):\n    client.get('/')\n"
    assert len(NoAssertionsRule().analyse(make_unit(method_src, "tests/views/tests.py"), default_ctx())) == 1
    assert NoAssertionsRule().analyse(make_unit(bare_src, "tests/views/tests.py"), default_ctx()) == []


def test_shipped_package_module_named_like_a_test_reports_nothing(tmp_path: Path) -> None:
    """Skip bandit/core/test_properties.py, whose test_id decorator factory ships with the package.

    Args:
        tmp_path: Temporary project root where the test creates bandit/core and the package initializer files.

    Returns:
        None. Checks that the decorator factory in the package module produces no findings.
    """
    (tmp_path / "bandit" / "core").mkdir(parents=True)
    (tmp_path / "bandit" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "bandit" / "core" / "__init__.py").write_text("", encoding="utf-8")
    src = "def test_id(id_val):\n    def _has_id(func):\n        func._test_id = id_val\n        return func\n    return _has_id\n"
    unit, context = _unit_under(tmp_path, "bandit/core/test_properties.py", src)
    assert NoAssertionsRule().analyse(unit, context) == []


def test_package_tests_directory_and_plain_directories_still_report(tmp_path: Path) -> None:
    """Report tests inside a package's tests directory and in a directory that is not a package.

    Args:
        tmp_path: Temporary project root where the test creates package initializer files and a tests directory.

    Returns:
        None. Checks for one finding at the package test path and one at the plain-directory path.
    """
    (tmp_path / "pkg" / "tests").mkdir(parents=True)
    (tmp_path / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "pkg" / "tests" / "__init__.py").write_text("", encoding="utf-8")
    src = "def test_api(client):\n    client.get('/')\n"
    in_package_tests, context = _unit_under(tmp_path, "pkg/tests/test_api.py", src)
    in_plain_directory, _ = _unit_under(tmp_path, "scripts/test_tool.py", src)
    assert len(NoAssertionsRule().analyse(in_package_tests, context)) == 1
    assert len(NoAssertionsRule().analyse(in_plain_directory, context)) == 1


def test_configured_python_files_replace_the_default_globs(tmp_path: Path) -> None:
    """Follow a project's own python_files setting instead of pytest's defaults.

    Args:
        tmp_path: Temporary project root where the test writes a pyproject.toml naming check_*.py.

    Returns:
        None. Checks for one finding at check_api.py and none at test_api.py under the configured glob.
    """
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\npython_files = ["check_*.py"]\n', encoding="utf-8")
    src = "def test_api(client):\n    client.get('/')\n"
    configured, context = _unit_under(tmp_path, "check_api.py", src)
    default_name, _ = _unit_under(tmp_path, "test_api.py", src)
    assert len(NoAssertionsRule().analyse(configured, context)) == 1
    assert NoAssertionsRule().analyse(default_name, context) == []


@pytest.mark.parametrize(
    ("config_files", "collected_path", "skipped_path"),
    [
        (
            {
                "pytest.ini": "[pytest]\npython_files = check_*.py\n",
                "pyproject.toml": '[tool.pytest.ini_options]\npython_files = ["spec_*.py"]\n',
            },
            "check_api.py",
            "spec_api.py",
        ),
        (
            {
                "pytest.ini": "",
                "pyproject.toml": '[tool.pytest.ini_options]\npython_files = ["spec_*.py"]\n',
            },
            "test_api.py",
            "spec_api.py",
        ),
        (
            {"tox.ini": "[pytest]\npython_files = check_*.py\n"},
            "check_api.py",
            "test_api.py",
        ),
        (
            {
                "tox.ini": "[tox]\nenvlist = py311\n",
                "setup.cfg": "[tool:pytest]\npython_files = spec_*.py\n",
            },
            "spec_api.py",
            "test_api.py",
        ),
    ],
    ids=["pytest-ini-beats-pyproject", "empty-pytest-ini-stops-fallback", "tox-ini-pytest", "setup-cfg-fallback"],
)
def test_ini_python_files_precedence(
    tmp_path: Path,
    config_files: dict[str, str],
    collected_path: str,
    skipped_path: str,
) -> None:
    """Resolve pytest python_files globs across pytest.ini, pyproject.toml, tox.ini, and setup.cfg in pytest order.

    Args:
        tmp_path: Temporary project root receiving the configuration files for this case.
        config_files: Mapping of config filenames to file contents written under tmp_path.
        collected_path: Relative test filename expected to be collected under the winning configuration.
        skipped_path: Relative filename expected to be ignored under the winning configuration.

    Returns:
        None. Checks that the collected file emits one finding while the skipped file emits none.
    """
    for filename, contents in config_files.items():
        (tmp_path / filename).write_text(contents, encoding="utf-8")
    source = "def test_api(client):\n    client.get('/')\n"
    collected, context = _unit_under(tmp_path, collected_path, source)
    skipped, _ = _unit_under(tmp_path, skipped_path, source)
    assert len(NoAssertionsRule().analyse(collected, context)) == 1
    assert NoAssertionsRule().analyse(skipped, context) == []


@pytest.mark.parametrize(
    "source",
    [
        "import nox\n@nox.session\ndef test_suite(session):\n    session.run('pytest')\n",
        "import nox\n@nox.session(python=['3.12'])\ndef test_suite(session):\n    session.run('pytest')\n",
        "from nox import session as nox_session\n@nox_session\ndef test_suite(session):\n    session.run('pytest')\n",
        "from invoke import task\n@task\ndef test_deploy(context):\n    context.run('deploy')\n",
    ],
    ids=["nox-session", "called-nox-session", "renamed-nox-session", "invoke-task"],
)
def test_task_runner_session_is_not_a_collected_test(source: str) -> None:
    """Skip functions a task runner calls, even when a test file names them test_*.

    Args:
        source: Python source defining a test-named function decorated as a Nox session or Invoke task.

    Returns:
        None. Checks that the supplied task-runner function produces no findings.
    """
    assert NoAssertionsRule().analyse(make_unit(source), default_ctx()) == []


def test_assertion_inside_a_nested_callback_counts() -> None:
    """Recognise verification inside a nested signal callback.

    Returns:
        None. Checks for no findings when the assertion is inside the nested signal callback.
    """
    src = (
        "def test_index(app, client):\n"
        "    def check(sender, template, context):\n"
        "        assert template.name == 'fetch.html'\n"
        "    with template_rendered.connected_to(check, app):\n"
        "        client.get('/')\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_assertion_helper_inside_a_lambda_counts() -> None:
    """Recognise an assertEqual call inside a lambda passed to another function.

    Returns:
        None. Checks that the assertion call inside the lambda produces no findings.
    """
    src = "class TestX:\n    def test_a(self):\n        run_later(lambda: self.assertEqual(1, 1))\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []
