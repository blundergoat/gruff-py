from gruffpy.rule.security.insecure_temp_file_rule import InsecureTempFileRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_tempfile_mktemp_emits():
    src = "import tempfile\npath = tempfile.mktemp()\n"
    findings = InsecureTempFileRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == "mktemp"


def test_bare_mktemp_emits():
    src = "from tempfile import mktemp\npath = mktemp()\n"
    findings = InsecureTempFileRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_tempfile_mkstemp_skipped():
    src = "import tempfile\nfd, path = tempfile.mkstemp()\n"
    assert InsecureTempFileRule().analyse(make_unit(src), default_ctx()) == []


def test_tempfile_namedtempfile_skipped():
    src = "import tempfile\nf = tempfile.NamedTemporaryFile()\n"
    assert InsecureTempFileRule().analyse(make_unit(src), default_ctx()) == []


def test_open_hardcoded_tmp_emits():
    src = "with open('/tmp/state.json', 'w') as f:\n    f.write('x')\n"
    findings = InsecureTempFileRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["path"] == "/tmp/state.json"


def test_path_hardcoded_tmp_emits():
    src = "from pathlib import Path\np = Path('/tmp/lock')\n"
    findings = InsecureTempFileRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_var_tmp_prefix_emits():
    src = "with open('/var/tmp/cache.bin', 'wb') as f:\n    f.write(b'')\n"
    findings = InsecureTempFileRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_shutil_copy_hardcoded_tmp_emits():
    src = "import shutil\nshutil.copyfile(src, '/tmp/out.bin')\n"
    findings = InsecureTempFileRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_open_non_tmp_path_skipped():
    src = "with open('/etc/config.json', 'r') as f:\n    f.read()\n"
    assert InsecureTempFileRule().analyse(make_unit(src), default_ctx()) == []


def test_open_dynamic_path_skipped():
    src = "import tempfile\npath = tempfile.gettempdir() + '/x'\nopen(path)\n"
    assert InsecureTempFileRule().analyse(make_unit(src), default_ctx()) == []


def test_open_tmp_prefix_only_match_does_not_fire():
    """A literal that begins with /tmp but is not under /tmp/ (e.g. /tmpfoo) skipped."""
    src = "open('/tmpfoo')\n"
    assert InsecureTempFileRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "import tempfile\npath = tempfile.mktemp()\n"
    finding = InsecureTempFileRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "temp-file-creation"
    assert finding.metadata["sourceLabel"] == "filesystem"
