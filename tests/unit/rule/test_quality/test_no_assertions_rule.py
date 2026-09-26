from dataclasses import replace
from pathlib import Path

import pytest

from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.test_quality.no_assertions_rule import NoAssertionsRule
from gruffpy.source.source_file import SourceFile
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_no_assert_emits():
    src = "def test_foo():\n    x = 1\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_collected_test_without_assertions_still_emits():
    src = "def test_missing_assertion():\n    exercise_system()\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_assert_skipped():
    src = "def test_foo():\n    assert 1 + 1 == 2\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_unittest_assert_method_counts_as_assertion() -> None:
    """Recognise unittest assertion methods as test verification."""
    src = "class TestX:\n    def test_a(self):\n        self.assertEqual(1, 1)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_pytest_raises_block_counts_as_assertion() -> None:
    """Recognise the canonical pytest exception context manager."""
    src = "import pytest\ndef test_foo():\n    with pytest.raises(ValueError):\n        raise ValueError\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_parametrized_pytest_raises_context_counts_as_assertion() -> None:
    """Recognise a verification context constructed by parametrisation."""
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
    """Recognise exception assertions through each supported pytest import form.

    Args:
        source: Test source using a direct, renamed, or module-aliased pytest helper.
    """
    assert NoAssertionsRule().analyse(make_unit(source), default_ctx()) == []


def test_pytest_warns_block_counts_as_assertion() -> None:
    """Recognise the canonical pytest warning context manager."""
    src = "import pytest\ndef test_value():\n    with pytest.warns(UserWarning):\n        warn_user()\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_pytest_fail_counts_as_assertion():
    src = "import pytest\ndef test_foo():\n    pytest.fail('bad branch')\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_warnings_catch_warnings_counts_as_assertion():
    src = (
        "import warnings\n"
        "def test_foo():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('error', RuntimeWarning)\n"
        "        run_without_warning()\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_warnings_filterwarnings_error_counts_as_assertion():
    src = (
        "import warnings\n"
        "def test_foo():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.filterwarnings('error')\n"
        "        run_without_warning()\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_bare_catch_warnings_without_error_filter_emits():
    src = "import warnings\ndef test_foo():\n    with warnings.catch_warnings():\n        do_work()\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_catch_warnings_with_ignore_filter_emits():
    src = "import warnings\ndef test_foo():\n    with warnings.catch_warnings():\n        warnings.simplefilter('ignore')\n        do_work()\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_bare_assert_helper_counts_as_assertion():
    src = "def test_image():\n    assert_image_mostly_same(actual, expected)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_dotted_assert_helper_counts_as_assertion():
    src = "def test_image():\n    helpers.assert_image_mostly_same(actual, expected)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_non_assert_helper_does_not_count():
    src = "def test_image():\n    compare_image(actual, expected)\n"
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_fixture_named_test_image_is_not_reported():
    src = "import pytest\n@pytest.fixture\ndef test_image():\n    return load_image()\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_called_fixture_named_test_image_is_not_reported():
    src = "from pytest import fixture\n@fixture()\ndef test_image():\n    return load_image()\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_conftest_fixture_factory_is_not_reported():
    src = "import pytest\n@pytest.fixture\ndef image_factory():\n    return ImageFactory()\n"
    assert NoAssertionsRule().analyse(make_unit(src, "tests/conftest.py"), default_ctx()) == []


def test_conftest_plain_support_function_is_not_reported():
    src = "def build_image():\n    return ImageFactory()\n"
    assert NoAssertionsRule().analyse(make_unit(src, "tests/conftest.py"), default_ctx()) == []


def test_non_test_function_skipped():
    src = "def helper():\n    x = 1\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def _unit_under(project_root: Path, display_path: str, source: str) -> tuple[AnalysisUnit, RuleContext]:
    """Place a parsed unit at *display_path* beneath a real project root.

    Args:
        project_root: Temporary project directory whose ``__init__.py`` files and settings the rule reads.
        display_path: Project-relative path of the analysed file.
        source: Python source to parse.

    Returns:
        The unit and a default-configured context rooted at *project_root*.
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
    """Skip the M17 hunt's non-collected shapes, whose ``test_*`` functions no runner executes.

    Args:
        display_path: Project-relative path pytest and unittest discovery both ignore.
    """
    src = "def test_shape(record):\n    return record\n"
    assert NoAssertionsRule().analyse(make_unit(src, display_path), default_ctx()) == []


@pytest.mark.parametrize(
    "display_path", ["test_guard.py", "tests/test_api.py", "src/app/api_test.py"], ids=["root-test-module", "tests-directory", "suffix-module"]
)
def test_collected_file_still_reports(display_path: str) -> None:
    """Keep reporting an assertion-free test in every file pytest collects by default.

    Args:
        display_path: Project-relative path matching pytest's default ``python_files`` globs.
    """
    src = "def test_without_assertion() -> int:\n    value = 1\n    return value\n"
    findings = NoAssertionsRule().analyse(make_unit(src, display_path), default_ctx())
    assert len(findings) == 1
    assert "delete the test" in (findings[0].remediation or "")


def test_unittest_discovery_file_reports_testcase_methods_only() -> None:
    """Report ``TestCase`` methods in a unittest-discovered ``tests.py`` but not bare functions there."""
    method_src = "import unittest\nclass ViewTests(unittest.TestCase):\n    def test_view(self):\n        self.client.get('/')\n"
    bare_src = "def test_view(client):\n    client.get('/')\n"
    assert len(NoAssertionsRule().analyse(make_unit(method_src, "tests/views/tests.py"), default_ctx())) == 1
    assert NoAssertionsRule().analyse(make_unit(bare_src, "tests/views/tests.py"), default_ctx()) == []


def test_shipped_package_module_named_like_a_test_reports_nothing(tmp_path: Path) -> None:
    """Skip ``bandit/core/test_properties.py``, whose ``test_id`` decorator factory ships with the package.

    Args:
        tmp_path: Temporary project root holding the package's ``__init__.py`` files.
    """
    (tmp_path / "bandit" / "core").mkdir(parents=True)
    (tmp_path / "bandit" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "bandit" / "core" / "__init__.py").write_text("", encoding="utf-8")
    src = "def test_id(id_val):\n    def _has_id(func):\n        func._test_id = id_val\n        return func\n    return _has_id\n"
    unit, context = _unit_under(tmp_path, "bandit/core/test_properties.py", src)
    assert NoAssertionsRule().analyse(unit, context) == []


def test_package_tests_directory_and_plain_directories_still_report(tmp_path: Path) -> None:
    """Report tests inside a package's ``tests`` directory and in a directory that is not a package.

    Args:
        tmp_path: Temporary project root holding one package with a tests directory.
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
    """Follow a project's own ``python_files`` setting instead of pytest's defaults.

    Args:
        tmp_path: Temporary project root with a ``pyproject.toml`` naming ``check_*.py``.
    """
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\npython_files = ["check_*.py"]\n', encoding="utf-8")
    src = "def test_api(client):\n    client.get('/')\n"
    configured, context = _unit_under(tmp_path, "check_api.py", src)
    default_name, _ = _unit_under(tmp_path, "test_api.py", src)
    assert len(NoAssertionsRule().analyse(configured, context)) == 1
    assert NoAssertionsRule().analyse(default_name, context) == []


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
    """Skip functions a task runner calls, even when a test file names them ``test_*``.

    Args:
        source: Task-runner function decorated through a supported import form.
    """
    assert NoAssertionsRule().analyse(make_unit(source), default_ctx()) == []


def test_assertion_inside_a_nested_callback_counts() -> None:
    """Recognise the Flask ``test_js_example.py`` shape, which asserts inside a signal callback."""
    src = (
        "def test_index(app, client):\n"
        "    def check(sender, template, context):\n"
        "        assert template.name == 'fetch.html'\n"
        "    with template_rendered.connected_to(check, app):\n"
        "        client.get('/')\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_assertion_helper_inside_a_lambda_counts() -> None:
    """Recognise a framework assertion a test hands to another call as a lambda."""
    src = "class TestX:\n    def test_a(self):\n        run_later(lambda: self.assertEqual(1, 1))\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []
