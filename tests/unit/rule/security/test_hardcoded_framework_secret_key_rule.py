from gruffpy.rule.security.hardcoded_framework_secret_key_rule import (
    HardcodedFrameworkSecretKeyRule,
)
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_django_settings_module_scope_secret_key_emits():
    """Report one finding for a module-level SECRET_KEY string literal in a module that imports Django settings.

    Returns:
        None when all assertions pass.
    """
    src = "from django.conf import settings\nSECRET_KEY = 'super-secret-please-change'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_flask_app_module_scope_secret_key_emits():
    """Report one finding for a short module-level SECRET_KEY literal in a Flask module.

    Returns:
        None when all assertions pass.
    """
    src = "from flask import Flask\nSECRET_KEY = 'dev'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    # Even short / obviously-dev strings fire - the shape is the smell.


def test_secret_key_from_env_skipped():
    """Report nothing when SECRET_KEY is read from os.environ.

    Returns:
        None when all assertions pass.
    """
    src = "import os\nfrom django.conf import settings\nSECRET_KEY = os.environ['SECRET_KEY']\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_secret_key_from_getenv_skipped():
    """Report nothing when SECRET_KEY is read with os.getenv.

    Returns:
        None when all assertions pass.
    """
    src = "import os\nfrom flask import Flask\nSECRET_KEY = os.getenv('SECRET_KEY', '')\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_function_scope_secret_key_skipped():
    """Expect no finding for a local SECRET_KEY assignment inside a function in a Flask module.

    Returns:
        None. Checks that the function-local SECRET_KEY assignment yields no findings.
    """
    src = "from flask import Flask\ndef setup():\n    SECRET_KEY = 'literal'\n    return SECRET_KEY\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_non_framework_file_skipped():
    """Expect no finding for a module-level SECRET_KEY string literal in a module without a recognised framework import.

    Returns:
        None. Checks that the module-level SECRET_KEY literal yields no findings in a module without a framework import.
    """
    src = "SECRET_KEY = 'literal'\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_annotated_assign_emits():
    """Report one finding for an annotated module-level ``SECRET_KEY`` literal in a Flask module.

    Returns:
        None after the assertion passes.
    """
    src = "from flask import Flask\nSECRET_KEY: str = 'literal'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_secret_key_assigned_non_string_skipped():
    """Expect no finding when a function call supplies the value of SECRET_KEY.

    Returns:
        None. Checks that assigning SECRET_KEY from generate_key() yields no findings.
    """
    src = "from flask import Flask\nSECRET_KEY = generate_key()\n"
    assert HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx()) == []


def test_rest_framework_file_also_triggers():
    """Report one finding for a module-level SECRET_KEY literal when rest_framework is imported.

    Returns:
        None when all assertions pass.
    """
    src = "from rest_framework.serializers import Serializer\nSECRET_KEY = 'literal'\n"
    findings = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    """Label the finding with the ``signing-key`` sink, the ``framework-config`` source and the ``SECRET_KEY`` name.

    Returns:
        None after the assertions pass.
    """
    src = "from flask import Flask\nSECRET_KEY = 'literal'\n"
    finding = HardcodedFrameworkSecretKeyRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "signing-key"
    assert finding.metadata["sourceLabel"] == "framework-config"
    assert finding.metadata["name"] == "SECRET_KEY"
