from gruffpy.rule.security.django_raw_sql_rule import DjangoRawSqlRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_raw_with_fstring_emits():
    src = (
        "from django.db import models\n"
        "def search(table, val):\n"
        "    return Model.objects.raw(f'SELECT * FROM {table} WHERE x={val}')\n"
    )
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == ".raw"


def test_raw_with_format_call_emits():
    src = (
        "from django.db import models\n"
        "def search(val):\n"
        "    return Model.objects.raw('SELECT * FROM t WHERE x={}'.format(val))\n"
    )
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_raw_with_percent_format_emits():
    src = (
        "from django.db import models\n"
        "def search(val):\n"
        "    return Model.objects.raw('SELECT * FROM t WHERE x=%s' % val)\n"
    )
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_raw_with_concat_emits():
    src = (
        "from django.db import models\n"
        "def search(val):\n"
        "    return Model.objects.raw('SELECT * FROM t WHERE x=' + val)\n"
    )
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_raw_with_string_literal_skipped():
    src = (
        "from django.db import models\n"
        "Model.objects.raw('SELECT * FROM t WHERE x = %s', [user_id])\n"
    )
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_rawsql_with_fstring_emits():
    src = (
        "from django.db.models.expressions import RawSQL\n"
        "def annotate(val):\n"
        "    return RawSQL(f'SUM(x) WHERE id = {val}', [])\n"
    )
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "RawSQL"


def test_rawsql_with_string_literal_skipped():
    src = (
        "from django.db.models.expressions import RawSQL\n"
        "RawSQL('SUM(x) WHERE id = %s', [value])\n"
    )
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_raw_in_non_django_file_skipped():
    """Non-Django file with .raw() doesn't fire (framework gate)."""
    src = "def search(val):\n    return socket.raw(f'data {val}')\n"
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_cursor_execute_dynamic_not_duplicated():
    """cursor.execute(dynamic) is sql-concatenation's territory; this rule must not fire."""
    src = (
        "from django.db import connection\n"
        "def search(val):\n"
        "    with connection.cursor() as cur:\n"
        "        cur.execute(f'SELECT * FROM t WHERE x={val}')\n"
    )
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = (
        "from django.db import models\n"
        "def search(val):\n"
        "    return Model.objects.raw(f'SELECT * FROM t WHERE x={val}')\n"
    )
    finding = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "django-orm-raw"
    assert finding.metadata["sourceLabel"] == "dynamic-sql"
