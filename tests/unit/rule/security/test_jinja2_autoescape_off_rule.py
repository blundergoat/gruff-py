from gruffpy.rule.security.jinja2_autoescape_off_rule import Jinja2AutoescapeOffRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_environment_no_autoescape_kwarg_emits():
    src = "import jinja2\nenv = jinja2.Environment(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_autoescape_false_emits():
    src = "import jinja2\nenv = jinja2.Environment(autoescape=False)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_autoescape_true_skipped():
    src = "import jinja2\nenv = jinja2.Environment(autoescape=True)\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_environment_with_select_autoescape_skipped():
    src = (
        "from jinja2 import Environment, select_autoescape\n"
        "env = Environment(autoescape=select_autoescape(['html', 'xml']))\n"
    )
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_environment_from_import_no_autoescape_emits():
    src = "from jinja2 import Environment\nenv = Environment(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_aliased_from_import_emits():
    src = "from jinja2 import Environment as Env\nenv = Env(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_aliased_module_import_emits():
    src = "import jinja2 as j2\nenv = j2.Environment(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unrelated_environment_class_not_flagged():
    """A non-jinja2 Environment(...) constructor must not fire (jinja2 not imported)."""
    src = "from some_lib import Environment\nenv = Environment(name='test')\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_environment_dynamic_autoescape_skipped_conservative():
    """Dynamic autoescape value (e.g. config lookup) is skipped - we cannot prove it's False."""
    src = "import jinja2\nenv = jinja2.Environment(autoescape=settings.AUTOESCAPE)\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "import jinja2\nenv = jinja2.Environment(loader=loader)\n"
    finding = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "html-output"
    assert finding.metadata["sourceLabel"] == "template-context"
    assert finding.metadata["target"] == "jinja2.Environment"


def test_only_jinja2_mention_in_docstring_does_not_fire():
    """The source-needle short-circuit short-circuits, but no env aliases means no fire."""
    src = '"""Notes on jinja2 vs mako."""\n'
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []
