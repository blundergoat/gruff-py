from gruff.rule.security.unsafe_pickle_rule import UnsafePickleRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


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


def test_json_loads_not_flagged():
    src = "import json\njson.loads(blob)\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []
