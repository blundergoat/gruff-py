from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.security.unsafe_pickle_rule import UnsafePickleRule
from tests.unit.rule.security._helpers import ctx_enabling, default_ctx, make_unit


def test_pickle_loads_variable_emits():
    src = "import pickle\nx = request_body\npickle.loads(x)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_pickle_loads_bytes_literal_skipped():
    src = "import pickle\npickle.loads(b'\\x80\\x04')\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_pickle_load_file_emits():
    src = "import pickle\nwith open('x', 'rb') as f:\n    pickle.load(f)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unpickler_load_emits():
    src = "import pickle\npickle.Unpickler(some_file).load()\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_dill_loads_variable_emits():
    src = "import dill\ndill.loads(blob)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_marshal_loads_variable_emits():
    src = "import marshal\nmarshal.loads(blob)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_marshal_load_file_emits():
    src = "import marshal\nwith open('x', 'rb') as f:\n    marshal.load(f)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_marshal_loads_bytes_literal_skipped():
    src = "import marshal\nmarshal.loads(b'\\x80\\x04')\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_shelve_open_variable_emits():
    src = "import shelve\nshelve.open(user_supplied_path)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_shelve_open_string_literal_skipped():
    src = "import shelve\nshelve.open('local_data')\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_jsonpickle_decode_variable_emits():
    src = "import jsonpickle\njsonpickle.decode(payload)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_jsonpickle_decode_string_literal_skipped():
    src = 'import jsonpickle\njsonpickle.decode(\'{"py/object": "x"}\')\n'
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_json_loads_not_flagged():
    src = "import json\njson.loads(blob)\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_default_off_and_explicit_enable_use_the_same_detector():
    """Keep the rule opt-in while preserving the existing positive fixture."""
    registry = RuleRegistry.defaults()
    unit = make_unit("import pickle\nx = request_body\npickle.loads(x)\n")
    assert not UnsafePickleRule().definition().default_enabled
    assert not any(finding.rule_id == UnsafePickleRule.ID for finding in registry.analyse([unit], default_ctx()))
    enabled = [finding for finding in registry.analyse([unit], ctx_enabling(UnsafePickleRule.ID)) if finding.rule_id == UnsafePickleRule.ID]
    assert len(enabled) == 1
