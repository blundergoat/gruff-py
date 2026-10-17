import pytest

from gruffpy.rule.docs.missing_return_doc_rule import MissingReturnDocRule
from tests.unit.rule.docs._helpers import default_ctx, every_callable_ctx, make_unit


def test_documented_returns_emits_nothing():
    src = 'def f() -> int:\n    """Get a thing.\n\n    Returns:\n        int: the thing.\n    """\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_non_none_return_without_section_emits():
    src = 'def f() -> int:\n    """Get a thing."""\n    return 1\n'
    findings = MissingReturnDocRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].symbol == "f"
    assert "no result description was recognized" in findings[0].message
    assert "Returns section" not in findings[0].message


def test_none_return_skipped():
    src = 'def f() -> None:\n    """Side effect."""\n    print(1)\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_no_annotation_skipped():
    src = 'def f():\n    """Get a thing."""\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_skipped():
    src = 'def _f() -> int:\n    """X."""\n    return 1\n'
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []


def test_private_function_reported_with_every_callable():
    src = 'def _f() -> int:\n    """X."""\n    return 1\n'
    findings = MissingReturnDocRule().analyse(make_unit(src), every_callable_ctx(MissingReturnDocRule.ID))
    assert [f.symbol for f in findings] == ["_f"]


def test_unannotated_value_return_reported_only_with_every_callable():
    src = (
        'def plain(x):\n    """Double."""\n    return x * 2\n\n'
        'async def fetch(x):\n    """Fetch."""\n    return x\n\n'
        'def silent(x):\n    """Log."""\n    print(x)\n    return None\n\n'
        'def gen(x):\n    """Count.\n\n    Yields:\n        int: each value.\n    """\n    yield x\n'
    )
    assert MissingReturnDocRule().analyse(make_unit(src), default_ctx()) == []
    findings = MissingReturnDocRule().analyse(make_unit(src), every_callable_ctx(MissingReturnDocRule.ID))
    assert sorted(f.symbol for f in findings) == ["fetch", "plain"]


@pytest.mark.parametrize(
    ("name", "docstring"),
    (
        ("score_case", "Score one case's raw response against its answer sheet; returns the per-case card."),
        ("to_native_string", "Given a string object, regardless of type, returns a representation of that string in the native string type."),
        ("get_value_or_default", "The first one to not be a DefaultPlaceholder will be returned."),
    ),
)
def test_explicit_result_prose_needs_no_returns_section(name, docstring):
    source = f'def {name}() -> object:\n    """{docstring}"""\n    return value\n'
    assert MissingReturnDocRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    ("name", "annotation", "docstring"),
    (
        ("LineMatcher_fixture", "type[LineMatcher]", "A reference to the LineMatcher class."),
        ("public_key", "DHPublicKey", "The DHPublicKey associated with this private key."),
    ),
)
def test_nominal_result_prose_names_the_annotated_class(name, annotation, docstring):
    source = f'def {name}() -> {annotation}:\n    """{docstring}"""\n    return value\n'
    assert MissingReturnDocRule().analyse(make_unit(source), default_ctx()) == []


def test_property_value_description_needs_no_returns_section():
    source = '''
class URL:
    @property
    def netloc(self) -> bytes:
        """Either <host> or <host>:<port> as bytes.
        Always normalized to lowercase, and IDNA encoded.
        """
        return self._uri_reference.authority
'''
    assert MissingReturnDocRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize("describe_fallback", (True, False), ids=("both-streams-described", "fallback-undocumented"))
def test_stream_prose_accounts_for_each_returned_value(describe_fallback):
    fallback = ", otherwise use sys.stderr" if describe_fallback else ""
    source = f'''
@LocalProxy
def wsgi_errors_stream() -> t.TextIO:
    """Find the most appropriate error stream for the application.
    If a request is active, log to wsgi.errors{fallback}.
    """
    if request:
        return request.environ["wsgi.errors"]
    return sys.stderr
'''
    findings = MissingReturnDocRule().analyse(make_unit(source), default_ctx())
    assert bool(findings) is not describe_fallback


def test_action_prose_without_a_result_description_still_emits():
    source = '''
def load_ssh_private_key(data) -> SSHPrivateKeyTypes:
    """Load private key from OpenSSH custom encoding."""
    return loaded_key
'''
    findings = MissingReturnDocRule().analyse(make_unit(source), default_ctx())
    assert [f.symbol for f in findings] == ["load_ssh_private_key"]


@pytest.mark.parametrize("key", ("", "id"), ids=("empty-key", "substring-only"))
def test_return_key_must_be_a_nonempty_reference_in_the_prose(key):
    source = f'''
def lookup() -> object:
    """Validate the configured lookup."""
    return settings[{key!r}]
'''
    findings = MissingReturnDocRule().analyse(make_unit(source), default_ctx())
    assert [f.symbol for f in findings] == ["lookup"]
