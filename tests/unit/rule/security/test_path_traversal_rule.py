from gruffpy.rule.security.path_traversal_rule import PathTraversalRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_open_tainted_path_emits():
    """Report one finding for ``open`` on a filename read from Flask request arguments."""
    src = "from flask import request\ndef view():\n    name = request.args['file']\n    open(name).read()\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_open_module_qualified_request_path_emits():
    """Flag the module-qualified Flask idiom reaching a filesystem sink."""
    src = "import flask\ndef view():\n    name = flask.request.args['file']\n    open(name).read()\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_open_application_object_request_path_skipped():
    """Keep an application object's request-shaped attribute quiet inside a web file."""
    src = "from flask import request\ndef view(other):\n    name = other.request.args['file']\n    open(name).read()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_open_literal_path_skipped():
    """Report nothing for ``open`` on a literal path."""
    src = "from flask import request\ndef view():\n    open('/etc/config.json').read()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_open_secure_filename_sanitised_skipped():
    """Report nothing when ``secure_filename`` cleans the request filename before ``open``."""
    src = (
        "from flask import request\n"
        "from werkzeug.utils import secure_filename\n"
        "def view():\n"
        "    name = request.args['file']\n"
        "    open(secure_filename(name)).read()\n"
    )
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_basename_sanitised_skipped():
    """Report nothing when ``os.path.basename`` cleans the request filename before ``open``."""
    src = "import os\nfrom flask import request\ndef view():\n    name = request.args['file']\n    open(os.path.basename(name)).read()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_path_chained_read_text_emits():
    """Report one finding for ``Path(...).read_text()`` on a request filename."""
    src = "from pathlib import Path\nfrom flask import request\ndef view():\n    name = request.args['file']\n    Path(name).read_text()\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_path_chained_write_bytes_emits():
    """Report one finding for ``Path(...).write_bytes()`` on a request filename."""
    src = "from pathlib import Path\nfrom flask import request\ndef view():\n    name = request.args['file']\n    Path(name).write_bytes(b'')\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_path_chained_literal_skipped():
    """Report nothing for ``Path(...).read_text()`` on a literal path."""
    src = "from pathlib import Path\nfrom flask import request\ndef view():\n    Path('/etc/config.json').read_text()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_shutil_copyfile_tainted_src_emits():
    """Report one finding for ``shutil.copyfile`` from a request filename."""
    src = "import shutil\nfrom flask import request\ndef view():\n    name = request.args['file']\n    shutil.copyfile(name, '/safe/dest')\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_os_remove_tainted_emits():
    """Report one finding for ``os.remove`` on a request filename."""
    src = "import os\nfrom flask import request\ndef view():\n    name = request.args['file']\n    os.remove(name)\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_fstring_path_emits():
    """Report one finding for ``open`` on an f-string path holding a request filename."""
    src = "from flask import request\ndef view():\n    name = request.args['file']\n    open(f'/uploads/{name}').read()\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_non_web_file_skipped():
    """Without a web-framework import, the rule does not run (no taint sources possible)."""
    src = "def view(user_input):\n    open(user_input).read()\n"
    assert PathTraversalRule().analyse(make_unit(src), default_ctx()) == []


def test_fastapi_query_parameter_emits():
    """Report one finding for ``open`` on a FastAPI ``Query`` parameter."""
    src = "from fastapi import FastAPI, Query\napp = FastAPI()\n@app.get('/')\ndef view(name: str = Query(...)):\n    open(name).read()\n"
    findings = PathTraversalRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    """Label the request-path finding with the ``filesystem`` sink and ``user-controlled-path`` source."""
    src = "from flask import request\ndef view():\n    open(request.args['file']).read()\n"
    finding = PathTraversalRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "filesystem"
    assert finding.metadata["sourceLabel"] == "user-controlled-path"
