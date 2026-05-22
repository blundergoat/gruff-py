from gruffpy.rule.test_quality.sut_not_called_rule import SutNotCalledRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


def test_test_with_sut_call_skipped():
    src = "def test_foo():\n    result = my_function(42)\n    assert result == 42\n"
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []


def test_test_with_only_mocks_emits():
    src = (
        "from unittest.mock import Mock\n"
        "def test_foo():\n"
        "    mock = Mock()\n"
        "    mock.assert_called()\n"
    )
    findings = SutNotCalledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_test_with_only_assertions_emits():
    src = "def test_foo():\n    assert True\n"
    findings = SutNotCalledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_test_with_pytest_raises_and_sut():
    src = (
        "import pytest\n"
        "def test_foo():\n"
        "    with pytest.raises(ValueError):\n"
        "        my_function(-1)\n"
    )
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []


def test_constant_contract_test_reading_imported_name_skipped():
    # Schema/constant contract tests assert against the *content* of an
    # imported module-level value (a prompt string, a list of allowed
    # values). The test is exercising the import; SUT-call detection
    # should treat the imported-name read as a SUT touch.
    # Source: 2026-05-23 healthkit dogfood.
    src = (
        "from x import BOOKING_AGENT_SYSTEM_PROMPT\n"
        "def test_prompt_does_not_contain_voice_guidance():\n"
        "    assert 'Voice STT mishears' not in BOOKING_AGENT_SYSTEM_PROMPT\n"
    )
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []


def test_model_fields_inspection_skipped():
    # Reading `.model_fields` on a pydantic model is exercising the schema
    # declaration, even though no method is called.
    src = (
        "from x import ReferralDetails\n"
        "def test_legacy_fields_removed():\n"
        "    assert 'specialist_name' not in ReferralDetails.model_fields\n"
    )
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []


def test_annotations_access_skipped_regardless_of_receiver():
    # `__annotations__` access is a schema-inspection accessor; it counts
    # as a SUT touch no matter where the receiver came from.
    src = (
        "def test_annotation_shape():\n"
        "    class Local:\n"
        "        x: int\n"
        "    assert Local.__annotations__['x'] is int\n"
    )
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []


def test_test_using_only_test_framework_imports_still_emits():
    # Sanity: importing pytest/unittest/mock and only invoking framework
    # helpers is still a no-SUT test. The framework-module exclusion
    # prevents the new "imported name read" check from masking these.
    src = "import pytest\ndef test_foo():\n    assert True\n"
    findings = SutNotCalledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_module_level_computed_constant_read_skipped():
    # Schema/prompt-contract tests read the SUT's source via a module-level
    # helper at import time and stash it in a constant; tests then assert
    # against the constant's content. The constant IS the SUT.
    # Source: 2026-05-23 healthkit dogfood
    # (test_file_metadata_builder_prompt.MODULE_SOURCE).
    src = (
        "import pathlib\n"
        "def _read_source():\n"
        "    return pathlib.Path(__file__).read_text()\n"
        "MODULE_SOURCE = _read_source()\n"
        "def test_prompt_pins_schema_clause():\n"
        "    assert 'must describe' in MODULE_SOURCE\n"
    )
    assert SutNotCalledRule().analyse(make_unit(src), default_ctx()) == []
