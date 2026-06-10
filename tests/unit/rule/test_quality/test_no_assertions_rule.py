from gruffpy.rule.test_quality.no_assertions_rule import NoAssertionsRule
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


def test_unittest_assert_method_skipped():
    src = "class TestX:\n    def test_a(self):\n        self.assertEqual(1, 1)\n"
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_pytest_raises_block_skipped():
    src = (
        "import pytest\n"
        "def test_foo():\n"
        "    with pytest.raises(ValueError):\n"
        "        raise ValueError\n"
    )
    assert NoAssertionsRule().analyse(make_unit(src), default_ctx()) == []


def test_parametrized_pytest_raises_context_skipped():
    src = (
        "import pytest\n"
        '@pytest.mark.parametrize("exception", [pytest.raises(ValueError)])\n'
        "def test_foo(exception):\n"
        "    with exception:\n"
        "        raise ValueError\n"
    )
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
    src = (
        "import warnings\ndef test_foo():\n    with warnings.catch_warnings():\n        do_work()\n"
    )
    findings = NoAssertionsRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_catch_warnings_with_ignore_filter_emits():
    src = (
        "import warnings\n"
        "def test_foo():\n"
        "    with warnings.catch_warnings():\n"
        "        warnings.simplefilter('ignore')\n"
        "        do_work()\n"
    )
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
