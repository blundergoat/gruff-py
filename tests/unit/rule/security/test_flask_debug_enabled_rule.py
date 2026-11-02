from gruffpy.rule.security.flask_debug_enabled_rule import FlaskDebugEnabledRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_app_run_debug_true_emits():
    """Report one finding, with shape ``.run(debug=True)``, for ``app.run(debug=True)`` in a Flask file."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
    findings = FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == ".run(debug=True)"


def test_app_run_debug_false_skipped():
    """Report nothing for ``app.run(debug=False)``."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=False)\n"
    assert FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx()) == []


def test_app_run_no_debug_kwarg_skipped():
    """Report nothing for ``app.run`` without a debug argument."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(host='0.0.0.0')\n"
    assert FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx()) == []


def test_app_run_debug_dynamic_skipped():
    """Report nothing for a debug flag read from the environment."""
    src = "from flask import Flask\napp = Flask(__name__)\nimport os\napp.run(debug=os.getenv('DEV'))\n"
    assert FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx()) == []


def test_config_debug_subscript_assign_emits():
    """Report one finding, with the config-subscript shape, for setting the ``DEBUG`` config key to True."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = True\n"
    findings = FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == ".config['DEBUG'] = True"


def test_config_debug_subscript_assign_false_skipped():
    """Report nothing for setting the ``DEBUG`` config key to False."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.config['DEBUG'] = False\n"
    assert FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx()) == []


def test_config_update_debug_true_emits():
    """Report one finding, with the config-update shape, for ``app.config.update(DEBUG=True)``."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.config.update(DEBUG=True)\n"
    findings = FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["shape"] == ".config.update(DEBUG=True)"


def test_config_update_debug_false_skipped():
    """Report nothing for ``app.config.update(DEBUG=False)``."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.config.update(DEBUG=False)\n"
    assert FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx()) == []


def test_non_flask_file_skipped():
    """A non-Flask file with the same shapes does not fire (framework gate)."""
    src = "app.run(debug=True)\napp.config['DEBUG'] = True\n"
    assert FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx()) == []


def test_other_run_with_debug_in_flask_file_emits():
    """In a Flask file, any *.run(debug=True) is flagged - framework gate is file-level."""
    src = "from flask import Flask\nfrom unrelated import worker\nworker.run(debug=True)\n"
    findings = FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_quart_app_run_debug_true_emits():
    """Quart shares Flask's framework label and the same Werkzeug debugger pattern."""
    src = "from quart import Quart\napp = Quart(__name__)\napp.run(debug=True)\n"
    findings = FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_carries_security_metadata():
    """Label the ``app.run(debug=True)`` finding with the ``werkzeug-debugger`` sink and ``flask-config`` source."""
    src = "from flask import Flask\napp = Flask(__name__)\napp.run(debug=True)\n"
    finding = FlaskDebugEnabledRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "werkzeug-debugger"
    assert finding.metadata["sourceLabel"] == "flask-config"
