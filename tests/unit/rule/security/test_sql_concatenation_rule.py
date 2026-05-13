from gruff.rule.security.sql_concatenation_rule import SqlConcatenationRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_fstring_to_execute_emits():
    src = "cursor.execute(f'SELECT * FROM t WHERE id = {user_id}')\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_format_to_execute_emits():
    src = "cursor.execute('SELECT * FROM t WHERE id = {}'.format(user_id))\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_percent_format_to_execute_emits():
    src = "cursor.execute('SELECT * FROM t WHERE id = %s' % user_id)\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_plus_concat_to_execute_emits():
    src = "cursor.execute('SELECT * FROM t WHERE id = ' + user_id)\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_static_literal_skipped():
    src = "cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))\n"
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_sqlalchemy_text_with_fstring_emits():
    src = "from sqlalchemy import text\nengine.execute(text(f'SELECT {col}'))\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    # text(f"...") fires (target = "text"); engine.execute receives the Call result,
    # not a string, so it doesn't fire.
    assert any(f.metadata["target"] == "text" for f in findings)
