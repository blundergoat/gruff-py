from gruffpy.rule.security.sql_concatenation_rule import SqlConcatenationRule
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


def test_params_do_not_excuse_user_interpolation():
    src = (
        'TABLE_PREFIX = "shop"\n'
        "cursor.execute(\n"
        "    f\"SELECT * FROM {TABLE_PREFIX}_orders WHERE name = '{user_name}'\",\n"
        "    (oid,),\n"
        ")\n"
    )
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["sourceLabel"] == "dynamic-sql"


def test_function_parameter_table_name_still_emits_with_params():
    src = (
        "def load(table, oid):\n"
        '    cursor.execute(f"SELECT * FROM {table} WHERE id = %s", (oid,))\n'
    )
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["sourceLabel"] == "dynamic-sql"


def test_fixed_sql_keyword_constant_plus_user_interpolation_emits():
    src = (
        'SQL_SELECT_PREFIX = "SELECT * FROM users WHERE name = \'"\n'
        'cursor.execute(SQL_SELECT_PREFIX + f"{user_name}\'", (oid,))\n'
    )
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["sourceLabel"] == "dynamic-sql"


def test_reassigned_module_constant_still_emits():
    src = (
        'TABLE_PREFIX = "shop"\n'
        'TABLE_PREFIX = "other"\n'
        'cursor.execute(f"SELECT * FROM {TABLE_PREFIX}_orders WHERE id = %s", (oid,))\n'
    )
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["sourceLabel"] == "dynamic-sql"


def test_static_literal_skipped():
    src = "cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,))\n"
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_quoted_dbapi_placeholder_with_parameters_emits():
    src = "cursor.execute(\"SELECT * FROM users WHERE username = '%s'\", username)\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert findings[0].metadata["sourceLabel"] == "quoted-placeholder"
    assert findings[0].metadata["sinkLabel"] == "sql-execution"


def test_unquoted_dbapi_placeholder_with_parameters_skipped():
    src = 'cursor.execute("SELECT * FROM users WHERE username = %s", username)\n'
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_quoted_placeholder_without_parameters_skipped():
    src = "cursor.execute(\"SELECT * FROM users WHERE username = '%s'\")\n"
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_sqlalchemy_text_with_fstring_emits():
    src = "from sqlalchemy import text\nengine.execute(text(f'SELECT {col}'))\n"
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    # text(f"...") fires (target = "text"); engine.execute receives the Call result,
    # not a string, so it doesn't fire.
    assert any(f.metadata["target"] == "text" for f in findings)


def test_execute_without_sql_keywords_skipped():
    src = 'runner.execute(f"convert {path}")\n'
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_widget_text_without_sqlalchemy_skipped():
    src = 'widget.text(f"DELETE {name} FROM the list?")\n'
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_module_constant_table_prefix_with_parameters_skipped():
    src = (
        'TABLE_PREFIX = "shop"\n'
        'cursor.execute(f"SELECT * FROM {TABLE_PREFIX}_orders WHERE id = %s", (oid,))\n'
    )
    assert SqlConcatenationRule().analyse(make_unit(src), default_ctx()) == []


def test_conditionally_rebound_module_constant_still_emits():
    src = (
        'TABLE = "users"\n'
        "if OVERRIDE:\n"
        "    TABLE = load_table_name()\n"
        'cursor.execute(f"SELECT * FROM {TABLE} WHERE id = %s", (oid,))\n'
    )
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_fully_dynamic_executescript_emits_without_keyword_evidence():
    src = 'conn.executescript(f"{script}")\n'
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_fully_dynamic_executemany_emits_without_keyword_evidence():
    src = 'cursor.executemany(f"{template}", rows)\n'
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_fully_dynamic_sqlalchemy_text_emits_without_keyword_evidence():
    src = 'from sqlalchemy import text\nstmt = text(f"{query}")\n'
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "text"


def test_dynamic_structure_message_preserves_parameterised_values_guidance():
    src = (
        "def load(table, oid):\n"
        '    cursor.execute(f"SELECT * FROM {table} WHERE id = %s", (oid,))\n'
    )
    findings = SqlConcatenationRule().analyse(make_unit(src), default_ctx())

    assert len(findings) == 1
    assert "dynamic SQL structure" in findings[0].message
    assert "Keep values parameterised" in findings[0].remediation
