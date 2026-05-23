from gruffpy.rule.security.path_traversal_rule import PathTraversalRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_open_tainted_path_emits():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    open(name).read()\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_open_literal_path_skipped():
    src = "from flask import request\ndef view():\n    open('/etc/config.json').read()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_open_secure_filename_sanitised_skipped():
    src = (
        "from flask import request\n"
        "from werkzeug.utils import secure_filename\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    open(secure_filename(name)).read()\n"
    )
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_basename_sanitised_skipped():
    src = (
        "import os\n"
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    open(os.path.basename(name)).read()\n"
    )
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_path_chained_read_text_emits():
    src = (
        "from pathlib import Path\n"
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    Path(name).read_text()\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_path_chained_write_bytes_emits():
    src = (
        "from pathlib import Path\n"
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    Path(name).write_bytes(b'')\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_path_chained_literal_skipped():
    src = (
        "from pathlib import Path\n"
        "from flask import request\n"
        "def view():\n"
        "    Path('/etc/config.json').read_text()\n"
    )
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_shutil_copyfile_tainted_src_emits():
    src = (
        "import shutil\n"
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    shutil.copyfile(name, '/safe/dest')\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_os_remove_tainted_emits():
    src = (
        "import os\n"
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    os.remove(name)\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_fstring_path_emits():
    src = (
        "from flask import request\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    open(f'/uploads/{name}').read()\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_web_file_skipped():
    """Without a web-framework import, the rule does not run (no taint sources possible)."""
    src = "def view(user_input):\n    open(user_input).read()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_fastapi_query_parameter_emits():
    src = (
        "from fastapi import FastAPI, Query\n"
        "app = FastAPI()\n"
        "@app.get('/')\n"
        "def view(name: str = Query(...)):\n"
        "    open(name).read()\n"
    )
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    src = "from flask import request\ndef view():\n    open(request.args['file']).read()\n"
    finding = PathTraversalRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "filesystem"
    assert finding.metadata["sourceLabel"] == "user-controlled-path"
