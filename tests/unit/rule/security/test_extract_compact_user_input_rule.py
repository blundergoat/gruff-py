from gruffpy.rule.security.extract_compact_user_input_rule import ExtractCompactUserInputRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_splat_request_json_emits():
    """Report one finding for a call that unpacks ``request.json`` as keyword arguments."""
    src = "from flask import request\nFoo(**request.json)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_request_form_emits():
    """Report one finding for a call that unpacks ``request.form``."""
    src = "process(**request.form)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_request_get_emits():
    """Report one finding for a call that unpacks ``request.GET``."""
    src = "dict(**request.GET)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_module_qualified_request_emits():
    """Match the module-qualified proxy, keeping this rule aligned with the taint helper."""
    src = "import flask\nFoo(**flask.request.json)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_application_object_request_skipped():
    """Keep an application object's request-shaped attribute out of findings."""
    src = "def send(other):\n    Foo(**other.request.json)\n"
    assert ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx()) == []


def test_splat_local_dict_skipped():
    """Report nothing for a call that unpacks a local dictionary."""
    src = "data = {'a': 1}\nFoo(**data)\n"
    assert ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx()) == []


def test_kwargs_not_splat_skipped():
    """Report nothing for a keyword argument read from one request field."""
    src = "Foo(x=request.json['x'])\n"
    assert ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx()) == []
