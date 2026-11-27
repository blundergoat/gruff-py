from gruffpy.rule.registry import RuleRegistry
from gruffpy.rule.security.unsafe_pickle_rule import UnsafePickleRule
from tests.unit.rule.security._helpers import ctx_enabling, default_ctx, make_unit


def test_pickle_loads_variable_emits():
    """Report one finding for pickle.loads on a variable.

    Returns:
        None. Fails the test if the rule returns a finding count other than one.
    """
    src = "import pickle\nx = request_body\npickle.loads(x)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_pickle_loads_bytes_literal_skipped():
    """Report nothing for pickle.loads on a bytes literal.

    Returns:
        None. Fails the test if the bytes-literal call produces a finding.
    """
    src = "import pickle\npickle.loads(b'\\x80\\x04')\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_pickle_load_file_emits():
    """Report one finding for pickle.load on an open file.

    Returns:
        None. Fails the test unless the open-file call produces one finding.
    """
    src = "import pickle\nwith open('x', 'rb') as f:\n    pickle.load(f)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unpickler_load_emits():
    """Report one finding for pickle.Unpickler(...).load().

    Returns:
        None. Fails the test unless the Unpickler call produces one finding.
    """
    src = "import pickle\npickle.Unpickler(some_file).load()\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_dill_loads_variable_emits():
    """Report one finding for dill.loads on a variable.

    Returns:
        None. Fails the test unless the dill call produces one finding.
    """
    src = "import dill\ndill.loads(blob)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_marshal_loads_variable_emits():
    """Report one finding for marshal.loads on a variable.

    Returns:
        None. Fails the test unless marshal.loads on the variable produces one finding.
    """
    src = "import marshal\nmarshal.loads(blob)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_marshal_load_file_emits():
    """Report one finding for marshal.load on an open file.

    Returns:
        None. Fails the test unless marshal.load on the open file produces one finding.
    """
    src = "import marshal\nwith open('x', 'rb') as f:\n    marshal.load(f)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_marshal_loads_bytes_literal_skipped():
    """Report nothing for marshal.loads on a bytes literal.

    Returns:
        None. Fails the test if marshal.loads on the bytes literal produces a finding.
    """
    src = "import marshal\nmarshal.loads(b'\\x80\\x04')\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_shelve_open_variable_emits():
    """Report one finding for shelve.open on a variable path.

    Returns:
        None. Fails the test unless shelve.open on the variable path produces one finding.
    """
    src = "import shelve\nshelve.open(user_supplied_path)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_shelve_open_string_literal_skipped():
    """Report nothing for shelve.open on a literal path.

    Returns:
        None. Fails the test if shelve.open on the literal path produces a finding.
    """
    src = "import shelve\nshelve.open('local_data')\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_jsonpickle_decode_variable_emits():
    """Report one finding for jsonpickle.decode on a variable.

    Returns:
        None. Fails the test unless decoding the variable produces one finding.
    """
    src = "import jsonpickle\njsonpickle.decode(payload)\n"
    findings = UnsafePickleRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_jsonpickle_decode_string_literal_skipped():
    """Report nothing for jsonpickle.decode on a string literal.

    Returns:
        None. Fails the test if decoding the string literal produces a finding.
    """
    src = 'import jsonpickle\njsonpickle.decode(\'{"py/object": "x"}\')\n'
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_json_loads_not_flagged():
    """Report nothing for json.loads.

    Returns:
        None. Fails the test if the unsafe-pickle rule flags the json.loads call.
    """
    src = "import json\njson.loads(blob)\n"
    assert UnsafePickleRule().analyse(make_unit(src), default_ctx()) == []


def test_default_off_and_explicit_enable_use_the_same_detector():
    """Verify that the rule is off by default and reports one finding for the same input when enabled.

    Returns:
        None. Fails the test if the rule's default setting or either registry result differs from that contract.
    """
    registry = RuleRegistry.defaults()
    unit = make_unit("import pickle\nx = request_body\npickle.loads(x)\n")
    assert not UnsafePickleRule().definition().default_enabled
    assert not any(finding.rule_id == UnsafePickleRule.ID for finding in registry.analyse([unit], default_ctx()))
    enabled = [finding for finding in registry.analyse([unit], ctx_enabling(UnsafePickleRule.ID)) if finding.rule_id == UnsafePickleRule.ID]
    assert len(enabled) == 1
