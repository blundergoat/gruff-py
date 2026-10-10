"""Exercise which test-body calls count as a mystery guest a user must isolate.

Constructors, hermetic temporary files, module-shadowing fixtures, and mock assertions are not guests; calls that
reach the network, a mail server, or a file outside the test's own directory still are.
"""

import pytest

from gruffpy.rule.test_quality.mystery_guest_rule import MysteryGuestRule
from tests.unit.rule.test_quality._helpers import default_ctx, make_unit


@pytest.mark.parametrize(
    "source",
    [
        "import requests\ndef test_jar():\n    jar = requests.cookies.RequestsCookieJar()\n    assert len(jar) == 0\n",
        (
            "import requests\ndef test_prepare():\n"
            "    prepared = requests.Request('GET', 'http://example.test').prepare()\n"
            "    assert prepared.method == 'GET'\n"
        ),
        (
            "def test_write(tmp_path):\n"
            "    with open(tmp_path / 'out.txt', 'w') as handle:\n"
            "        handle.write('x')\n"
            "    assert (tmp_path / 'out.txt').exists()\n"
        ),
        ("def test_resolve(socket):\n    socket.gethostbyname('example.test')\n    socket.gethostbyname.assert_called_once_with('example.test')\n"),
    ],
    ids=["cookie-jar-constructor", "request-constructor", "open-under-tmp-path", "module-shadowing-fixture"],
)
def test_calls_that_perform_no_external_io_report_nothing(source: str) -> None:
    """Clear the M17 hunt's constructor, ``tmp_path`` and shadowing-parameter shapes.

    Args:
        source: Test body whose calls are hermetic.
    """
    assert MysteryGuestRule().analyse(make_unit(source), default_ctx()) == []


@pytest.mark.parametrize(
    ("source", "target"),
    [
        ("import requests\ndef test_fetch():\n    assert requests.get('http://example.test').ok\n", "requests.get"),
        ("def test_read():\n    assert open('/tmp/example.txt').read()\n", "open"),
        ("import requests\ndef test_session():\n    session = requests.Session()\n    assert session.get('http://example.test').ok\n", "session.get"),
        (
            "import httpx\ndef test_client():\n    with httpx.Client() as client:\n        assert client.post('http://example.test').is_success\n",
            "client.post",
        ),
        ("import requests\ndef test_inline():\n    assert requests.Session().get('http://example.test').ok\n", "requests.Session().get"),
        (
            (
                "import requests\ndef test_first():\n"
                "    prepared = requests.Request('GET', 'http://example.test').prepare()\n"
                "    assert requests.post('http://example.test', data=prepared.body).ok\n"
            ),
            "requests.post",
        ),
    ],
    ids=["module-helper", "absolute-file", "assigned-session", "with-client", "inline-session", "first-effectful-call"],
)
def test_calls_that_reach_external_state_still_report(source: str, target: str) -> None:
    """Keep reporting the first call that reaches the network or a shared file.

    Args:
        source: Test body making an effectful call.
        target: Dotted call the finding must name.
    """
    findings = MysteryGuestRule().analyse(make_unit(source), default_ctx())

    assert [finding.metadata["target"] for finding in findings] == [target]
