from gruffpy.rule.security.django_raw_sql_rule import DjangoRawSqlRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_raw_with_fstring_emits():
    """Report one finding, with shape .raw, for a Django raw query built with an f-string.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db import models\ndef search(table, val):\n    return Model.objects.raw(f'SELECT * FROM {table} WHERE x={val}')\n"
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == ".raw"


def test_raw_with_format_call_emits():
    """Report one finding for a raw query built with str.format.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db import models\ndef search(val):\n    return Model.objects.raw('SELECT * FROM t WHERE x={}'.format(val))\n"
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_raw_with_percent_format_emits():
    """Report one finding for a raw query built with percent formatting.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db import models\ndef search(val):\n    return Model.objects.raw('SELECT * FROM t WHERE x=%s' % val)\n"
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_raw_with_concat_emits():
    """Report one finding for a raw query built by concatenation.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db import models\ndef search(val):\n    return Model.objects.raw('SELECT * FROM t WHERE x=' + val)\n"
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_raw_with_string_literal_skipped():
    """Report nothing for a literal raw query with separate parameters.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db import models\nModel.objects.raw('SELECT * FROM t WHERE x = %s', [user_id])\n"
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_rawsql_with_fstring_emits():
    """Report one finding, with shape RawSQL, for a RawSQL expression built with an f-string.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db.models.expressions import RawSQL\ndef annotate(val):\n    return RawSQL(f'SUM(x) WHERE id = {val}', [])\n"
    findings = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "RawSQL"


def test_rawsql_with_string_literal_skipped():
    """Report nothing for a literal RawSQL expression with separate parameters.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db.models.expressions import RawSQL\nRawSQL('SUM(x) WHERE id = %s', [value])\n"
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_raw_in_non_django_file_skipped():
    """Non-Django file with .raw() doesn't fire (framework gate).

    Returns:
        None after the assertions pass.
    """
    src = "def search(val):\n    return socket.raw(f'data {val}')\n"
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_cursor_execute_dynamic_not_duplicated():
    """Check the Django raw-SQL rule on a cursor.execute call with an interpolated SQL string.

    Returns:
        None. Asserts that the f-string query produces an empty findings list.
    """
    src = (
        "from django.db import connection\n"
        "def search(val):\n"
        "    with connection.cursor() as cur:\n"
        "        cur.execute(f'SELECT * FROM t WHERE x={val}')\n"
    )
    assert DjangoRawSqlRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    """Label the f-string raw finding with the django-orm-raw sink and dynamic-sql source.

    Returns:
        None after the assertions pass.
    """
    src = "from django.db import models\ndef search(val):\n    return Model.objects.raw(f'SELECT * FROM t WHERE x={val}')\n"
    finding = DjangoRawSqlRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "django-orm-raw"
    assert finding.metadata["sourceLabel"] == "dynamic-sql"
