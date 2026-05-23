from gruffpy.rule.security.hardcoded_framework_secret_key_rule import (
    HardcodedFrameworkSecretKeyRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_django_settings_module_scope_secret_key_emits():
    src = "from django.conf import settings\nSECRET_KEY = 'super-secret-please-change'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_flask_app_module_scope_secret_key_emits():
    src = "from flask import Flask\nSECRET_KEY = 'dev'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    # Even short / obviously-dev strings fire - the shape is the smell.


def test_secret_key_from_env_skipped():
    src = "import os\nfrom django.conf import settings\nSECRET_KEY = os.environ['SECRET_KEY']\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_secret_key_from_getenv_skipped():
    src = "import os\nfrom flask import Flask\nSECRET_KEY = os.getenv('SECRET_KEY', '')\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_function_scope_secret_key_skipped():
    """SECRET_KEY inside a function is a local variable, not the framework setting."""
    src = (
        "from flask import Flask\ndef setup():\n    SECRET_KEY = 'literal'\n    return SECRET_KEY\n"
    )
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_non_framework_file_skipped():
    """A plain module with SECRET_KEY = '...' doesn't fire (no framework gate)."""
    src = "SECRET_KEY = 'literal'\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_annotated_assign_emits():
    src = "from flask import Flask\nSECRET_KEY: str = 'literal'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_secret_key_assigned_non_string_skipped():
    """SECRET_KEY = some_call() doesn't match the literal shape."""
    src = "from flask import Flask\nSECRET_KEY = generate_key()\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_rest_framework_file_also_triggers():
    """rest_framework maps to django framework label."""
    src = "from rest_framework.serializers import Serializer\nSECRET_KEY = 'literal'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    src = "from flask import Flask\nSECRET_KEY = 'literal'\n"
    finding = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "signing-key"
    assert finding.metadata["sourceLabel"] == "framework-config"
    assert finding.metadata["name"] == "SECRET_KEY"
