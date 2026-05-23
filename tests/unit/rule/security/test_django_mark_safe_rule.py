from gruffpy.rule.security.django_mark_safe_rule import DjangoMarkSafeRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_mark_safe_with_variable_emits():
    src = "from django.utils.safestring import mark_safe\ndef render(x):\n    return mark_safe(x)\n"
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["leaf"] == "mark_safe"


def test_mark_safe_with_fstring_emits():
    src = (
        "from django.utils.safestring import mark_safe\n"
        "def render(x):\n    return mark_safe(f'<b>{x}</b>')\n"
    )
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_mark_safe_with_string_literal_skipped():
    src = "from django.utils.safestring import mark_safe\nmark_safe('<br/>')\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_mark_safe_with_escape_call_skipped():
    src = (
        "from django.utils.safestring import mark_safe\n"
        "from django.utils.html import escape\n"
        "def render(x):\n    return mark_safe(escape(x))\n"
    )
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_mark_safe_with_conditional_escape_skipped():
    src = (
        "from django.utils.safestring import mark_safe\n"
        "from django.utils.html import conditional_escape\n"
        "def render(x):\n    return mark_safe(conditional_escape(x))\n"
    )
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_safestring_with_variable_emits():
    src = (
        "from django.utils.safestring import SafeString\ndef render(x):\n    return SafeString(x)\n"
    )
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["leaf"] == "SafeString"


def test_format_html_dynamic_template_emits():
    src = (
        "from django.utils.html import format_html\n"
        "def render(template, x):\n    return format_html(template, x)\n"
    )
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["leaf"] == "format_html"


def test_format_html_literal_template_skipped():
    """format_html with a literal template escapes its args — the standard safe pattern."""
    src = (
        "from django.utils.html import format_html\n"
        "def render(x):\n    return format_html('<b>{}</b>', x)\n"
    )
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_dotted_mark_safe_call_emits():
    src = (
        "import django.utils.safestring\n"
        "def render(x):\n    return django.utils.safestring.mark_safe(x)\n"
    )
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_django_file_skipped():
    """File without Django import — same shapes do not fire."""
    src = "def mark_safe(x):\n    return x\nmark_safe(payload)\n"
    assert DjangoMarkSafeRule().analyse(make_unit(src), default_ctx()) == []


def test_rest_framework_file_also_triggers_django_gate():
    """rest_framework is mapped to the django framework label by the helper."""
    src = (
        "from rest_framework.serializers import Serializer\n"
        "from django.utils.safestring import mark_safe\n"
        "def render(x):\n    return mark_safe(x)\n"
    )
    findings = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    src = "from django.utils.safestring import mark_safe\ndef render(x):\n    return mark_safe(x)\n"
    finding = DjangoMarkSafeRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "django-safe-marker"
    assert finding.metadata["sourceLabel"] == "user-html-input"
