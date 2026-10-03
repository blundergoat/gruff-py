import pytest

from gruffpy.rule.security.django_mark_safe_rule import DjangoMarkSafeRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_mark_safe_with_variable_emits():
    src = "from django.utils.safestring import mark_safe\ndef render(x):\n    return mark_safe(x)\n"
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["leaf"] == "mark_safe"


def test_mark_safe_with_fstring_emits():
    src = "from django.utils.safestring import mark_safe\ndef render(x):\n    return mark_safe(f'<b>{x}</b>')\n"
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_mark_safe_with_string_literal_skipped():
    src = "from django.utils.safestring import mark_safe\nmark_safe('<br/>')\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_mark_safe_with_escape_call_skipped():
    src = "from django.utils.safestring import mark_safe\nfrom django.utils.html import escape\ndef render(x):\n    return mark_safe(escape(x))\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_mark_safe_with_conditional_escape_skipped():
    src = (
        "from django.utils.safestring import mark_safe\n"
        "from django.utils.html import conditional_escape\n"
        "def render(x):\n    return mark_safe(conditional_escape(x))\n"
    )
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_safestring_with_variable_emits():
    src = "from django.utils.safestring import SafeString\ndef render(x):\n    return SafeString(x)\n"
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["leaf"] == "SafeString"


def test_format_html_dynamic_template_emits():
    src = "from django.utils.html import format_html\ndef render(template, x):\n    return format_html(template, x)\n"
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["leaf"] == "format_html"


def test_format_html_literal_template_skipped():
    """format_html with a literal template escapes its args - the standard safe pattern."""
    src = "from django.utils.html import format_html\ndef render(x):\n    return format_html('<b>{}</b>', x)\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_dotted_mark_safe_call_emits():
    src = "import django.utils.safestring\ndef render(x):\n    return django.utils.safestring.mark_safe(x)\n"
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_django_file_skipped():
    """File without Django import - same shapes do not fire."""
    src = "def mark_safe(x):\n    return x\nmark_safe(payload)\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_rest_framework_file_also_triggers_django_gate():
    """rest_framework is mapped to the django framework label by the helper."""
    src = (
        "from rest_framework.serializers import Serializer\nfrom django.utils.safestring import mark_safe\ndef render(x):\n    return mark_safe(x)\n"
    )
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    src = "from django.utils.safestring import mark_safe\ndef render(x):\n    return mark_safe(x)\n"
    finding = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "django-safe-marker"
    assert finding.metadata["sourceLabel"] == "user-html-input"


def test_mark_safe_with_literal_only_local_skipped():
    # Case 220: every binding of the local is a plain string literal, so it can only hold trusted markup.
    src = (
        "from django.utils.safestring import mark_safe\n"
        "LABEL = '<b>module</b>'\n"
        "mark_safe(LABEL)\n"
        "def render():\n"
        "    example = 'Example of link: <a href=\"http://www.example.com/\">example</a>'\n"
        "    return mark_safe(example)\n"
        "def render_branches(flag):\n"
        "    if flag:\n"
        "        label = '<b>on</b>'\n"
        "    else:\n"
        "        label = '<b>off</b>'\n"
        "    return mark_safe(label)\n"
    )
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


@pytest.mark.parametrize(
    "body",
    [
        "    value = '<b>ok</b>'\n    value = request\n    return mark_safe(value)\n",
        "    value = '<b>ok</b>'\n    value += request\n    return mark_safe(value)\n",
        "    value: str = request\n    return mark_safe(value)\n",
        "    value, _ = ('<b>ok</b>', '')\n    return mark_safe(value)\n",
        "    for value in request:\n        pass\n    return mark_safe(value)\n",
        "    with open(request) as value:\n        pass\n    return mark_safe(value)\n",
        "    try:\n        value = '<b>ok</b>'\n    except ValueError as value:\n        pass\n    return mark_safe(value)\n",
        "    if (value := request):\n        pass\n    return mark_safe(value)\n",
        "    import value\n    return mark_safe(value)\n",
        "    value = '<b>ok</b>'\n    del value\n    return mark_safe(value)\n",
        "    value = '<b>ok</b>'\n    def inner():\n        nonlocal value\n        value = request\n    inner()\n    return mark_safe(value)\n",
        "    global SHARED\n    SHARED = '<b>ok</b>'\n    return mark_safe(SHARED)\n",
        "    return mark_safe(request)\n",
        "    return mark_safe(SHARED)\n",
    ],
    ids=[
        "rebound",
        "augmented",
        "annotated-non-literal",
        "unpacked",
        "loop-target",
        "with-target",
        "except-target",
        "walrus",
        "import",
        "deleted",
        "nonlocal-rebind",
        "global",
        "parameter",
        "outer-scope-literal",
    ],
)
def test_mark_safe_with_non_literal_binding_emits(body: str) -> None:
    src = "from django.utils.safestring import mark_safe\nSHARED = '<b>module</b>'\ndef render(request):\n" + body
    assert len(DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())) == 1


def test_module_literal_rebound_through_global_emits():
    src = (
        "from django.utils.safestring import mark_safe\n"
        "LABEL = '<b>module</b>'\n"
        "def poison(request):\n"
        "    global LABEL\n"
        "    LABEL = request\n"
        "mark_safe(LABEL)\n"
    )
    assert len(DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())) == 1


def test_escaped_join_of_django_html_calls_skipped():
    # Case 223: an escaped separator joining Django's escaping calls builds only escaped markup.
    src = (
        "from django.utils.html import conditional_escape, format_html\n"
        "from django.utils.safestring import mark_safe\n"
        "def rows(sep, users):\n"
        "    return mark_safe(conditional_escape(sep).join(format_html('<li>{}</li>', user) for user in users))\n"
        "def cells(names):\n"
        "    return mark_safe('<br>'.join([conditional_escape(name) for name in names]))\n"
    )
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_escaped_join_inside_django_html_module_skipped():
    src = (
        "from django.utils.safestring import mark_safe\n"
        "def conditional_escape(text):\n    return text\n"
        "def format_html(format_string, *args):\n    return format_string\n"
        "def format_html_join(sep, args_generator):\n"
        "    return mark_safe(\n"
        "        conditional_escape(sep).join(\n"
        "            (format_html('<li>{a}</li>', **args) if isinstance(args, dict) else format_html('<li>{}</li>', *args))\n"
        "            for args in args_generator\n"
        "        )\n"
        "    )\n"
    )
    unit = make_unit(src, display_path="django/utils/html.py")
    assert DjangoMarkSafeRule().analyse(unit, default_ctx()) == []


@pytest.mark.parametrize(
    ("src", "display_path"),
    [
        (
            "from django.utils.html import format_html\nfrom django.utils.safestring import mark_safe\n"
            "def rows(sep, users):\n    return mark_safe(sep.join(format_html('<li>{}</li>', u) for u in users))\n",
            "app/views.py",
        ),
        (
            "from django.utils.html import conditional_escape\nfrom django.utils.safestring import mark_safe\n"
            "def rows(sep, users):\n    return mark_safe(conditional_escape(sep).join(users))\n",
            "app/views.py",
        ),
        (
            "from django.utils.html import conditional_escape\nfrom django.utils.safestring import mark_safe\n"
            "def rows(sep, users):\n    return mark_safe(conditional_escape(sep).join(str(u) for u in users))\n",
            "app/views.py",
        ),
        (
            "from django.utils.safestring import mark_safe\n"
            "def conditional_escape(text):\n    return text\n"
            "def rows(sep, users):\n    return mark_safe(conditional_escape(sep).join(conditional_escape(u) for u in users))\n",
            "app/html.py",
        ),
        (
            "from lookalike.html import conditional_escape\nfrom django.utils.safestring import mark_safe\n"
            "def rows(sep, users):\n    return mark_safe(conditional_escape(sep).join(conditional_escape(u) for u in users))\n",
            "app/views.py",
        ),
        (
            "from django.utils.html import format_html as conditional_escape\nfrom django.utils.safestring import mark_safe\n"
            "def rows(sep, users):\n    return mark_safe(conditional_escape(sep).join(conditional_escape('<li>{}</li>', u) for u in users))\n",
            "app/views.py",
        ),
        (
            "from django.utils.html import format_html\nfrom django.utils.safestring import mark_safe\n"
            "def rows(users):\n    return mark_safe('<br>'.join(format_html('<li>{}</li>', u) if u else u for u in users))\n",
            "app/views.py",
        ),
    ],
    ids=[
        "unescaped-separator",
        "raw-items",
        "stringified-items",
        "same-name-local-helper",
        "same-name-imported-helper",
        "renamed-django-helper",
        "conditional-with-raw-branch",
    ],
)
def test_unproven_joins_emit(src: str, display_path: str) -> None:
    assert len(DjangoMarkSafeRule().analyse(make_unit(src, display_path=display_path), default_ctx())) == 1


@pytest.mark.parametrize(
    "body",
    [
        "from django.utils.html import escape as esc\nesc = lambda value: value\ndef render(user):\n    return mark_safe(''.join([esc(user)]))\n",
        "from django.utils.html import escape\ndef render(escape, user):\n    return mark_safe(''.join([escape(user)]))\n",
        "import django.utils.html as html\nhtml = unknown\ndef render(user):\n    return mark_safe(''.join([html.escape(user)]))\n",
        "from django.utils import html\ndef render(html, user):\n    return mark_safe(''.join([html.escape(user)]))\n",
        "from django.utils.html import escape as esc\nfrom custom import raw as esc\ndef render(user):\n    return mark_safe(''.join([esc(user)]))\n",
        "from .django.utils.html import escape as esc\ndef render(user):\n    return mark_safe(''.join([esc(user)]))\n",
        "from django.utils.html import escape as esc\ndef esc(value):\n    return value\n"
        "def render(user):\n    return mark_safe(''.join([esc(user)]))\n",
        "from django.utils.html import escape as esc\ndef render(users):\n    return mark_safe(''.join(esc(user) for esc, user in users))\n",
        "import django.utils.html as html\nhtml.escape = lambda value: value\n"
        "def render(user):\n    return mark_safe(''.join([html.escape(user)]))\n",
    ],
    ids=[
        "alias-reassigned",
        "parameter-shadow",
        "module-reassigned",
        "module-parameter",
        "alias-imported-again",
        "relative-lookalike",
        "alias-function",
        "comprehension-shadow",
        "module-helper-reassigned",
    ],
)
def test_rebound_join_helpers_keep_warning(body: str) -> None:
    src = "from django.utils.safestring import mark_safe\n" + body
    assert len(DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())) == 1


@pytest.mark.parametrize(
    ("binding", "helper"),
    [
        ("from django.utils.html import escape as esc", "esc"),
        ("import django.utils.html as html", "html.escape"),
        ("from django.utils import html", "html.escape"),
    ],
    ids=["aliased-escape-import", "aliased-html-module", "html-submodule-import"],
)
def test_unmodified_join_helper_aliases_stay_quiet(binding: str, helper: str) -> None:
    src = f"from django.utils.safestring import mark_safe\n{binding}\ndef render(user):\n    return mark_safe(''.join([{helper}(user)]))\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []
