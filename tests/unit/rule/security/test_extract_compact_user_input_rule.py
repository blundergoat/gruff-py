from gruffpy.rule.security.extract_compact_user_input_rule import ExtractCompactUserInputRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_splat_request_json_emits():
    src = "from flask import request\nFoo(**request.json)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_request_form_emits():
    src = "process(**request.form)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_request_get_emits():
    src = "dict(**request.GET)\n"
    findings = ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_splat_local_dict_skipped():
    src = "data = {'a': 1}\nFoo(**data)\n"
    assert ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx()) == []


def test_kwargs_not_splat_skipped():
    src = "Foo(x=request.json['x'])\n"
    assert ExtractCompactUserInputRule().analyse(make_unit(src), default_ctx()) == []
