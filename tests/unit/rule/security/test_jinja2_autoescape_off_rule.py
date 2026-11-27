from gruffpy.rule.security.jinja2_autoescape_off_rule import Jinja2AutoescapeOffRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_environment_no_autoescape_kwarg_emits():
    """Report one finding for jinja2.Environment without an autoescape argument.

    Returns:
        None. Asserts that omitting autoescape from the constructor call produces one finding.
    """
    src = "import jinja2\nenv = jinja2.Environment(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_autoescape_false_emits():
    """Report one finding for jinja2.Environment(autoescape=False).

    Returns:
        None. Asserts that explicitly setting autoescape to False produces one finding.
    """
    src = "import jinja2\nenv = jinja2.Environment(autoescape=False)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_autoescape_true_skipped():
    """Report nothing for jinja2.Environment(autoescape=True).

    Returns:
        None. Asserts that explicitly setting autoescape to True produces no findings.
    """
    src = "import jinja2\nenv = jinja2.Environment(autoescape=True)\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_environment_with_select_autoescape_skipped():
    """Report nothing for an Environment that uses select_autoescape.

    Returns:
        None. Asserts that using select_autoescape to supply the autoescape argument produces no findings.
    """
    src = "from jinja2 import Environment, select_autoescape\nenv = Environment(autoescape=select_autoescape(['html', 'xml']))\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_environment_from_import_no_autoescape_emits():
    """Report one finding when a call to the directly imported jinja2.Environment omits autoescape.

    Returns:
        None. Checks the finding count for the unqualified Environment call.
    """
    src = "from jinja2 import Environment\nenv = Environment(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_aliased_from_import_emits():
    """Report one finding when a call to jinja2.Environment imported as Env omits autoescape.

    Returns:
        None. Checks the finding count for the Env call.
    """
    src = "from jinja2 import Environment as Env\nenv = Env(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_environment_aliased_module_import_emits():
    """Report one finding when Environment is called through a jinja2 module alias without autoescape.

    Returns:
        None. Checks the finding count for the j2.Environment call.
    """
    src = "import jinja2 as j2\nenv = j2.Environment(loader=loader)\n"
    findings = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_unrelated_environment_class_not_flagged():
    """A non-jinja2 Environment(...) constructor must not fire (jinja2 not imported).

    Returns:
        None. Asserts that calling some_lib.Environment produces no findings.
    """
    src = "from some_lib import Environment\nenv = Environment(name='test')\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_environment_dynamic_autoescape_skipped_conservative():
    """Dynamic autoescape value (e.g. config lookup) is skipped - we cannot prove it's False.

    Returns:
        None. Asserts that taking autoescape from settings.AUTOESCAPE produces no findings.
    """
    src = "import jinja2\nenv = jinja2.Environment(autoescape=settings.AUTOESCAPE)\n"
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    """Label the finding with the html-output sink, template-context source and jinja2.Environment target.

    Returns:
        None. Checks the sink, source and target metadata on the first finding.
    """
    src = "import jinja2\nenv = jinja2.Environment(loader=loader)\n"
    finding = Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "html-output"
    assert finding.metadata["sourceLabel"] == "template-context"
    assert finding.metadata["target"] == "jinja2.Environment"


def test_only_jinja2_mention_in_docstring_does_not_fire():
    """Report nothing when jinja2 appears only in a module docstring.

    Returns:
        None. Asserts that mentioning jinja2 only in a module docstring produces no findings.
    """
    src = '"""Notes on jinja2 vs mako."""\n'
    assert Jinja2AutoescapeOffRule().analyse(make_unit(src), default_ctx()) == []
