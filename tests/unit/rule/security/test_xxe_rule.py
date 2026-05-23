from gruffpy.rule.security.xxe_rule import XxeRule
from tests.unit.rule.security._helpers import default_ctx, make_unit


def test_etree_parse_via_aliased_import_emits():
    src = "import xml.etree.ElementTree as ET\ntree = ET.parse('x.xml')\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "xml.etree.ElementTree.parse"


def test_etree_fromstring_via_from_import_emits():
    src = "from xml.etree import ElementTree as ET\nET.fromstring(payload)\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "xml.etree.ElementTree.fromstring"


def test_etree_parse_via_direct_function_import_emits():
    src = "from xml.etree.ElementTree import parse\nparse('x.xml')\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_sax_parse_emits():
    src = "import xml.sax\nxml.sax.parse(stream, handler)\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_minidom_parse_emits():
    src = "import xml.dom.minidom\nxml.dom.minidom.parse(stream)\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_pulldom_parse_string_emits():
    src = "from xml.dom import pulldom\npulldom.parseString(payload)\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_lxml_etree_parse_emits():
    src = "from lxml import etree\netree.parse('x.xml')\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["target"] == "lxml.etree.parse"


def test_lxml_etree_fromstring_emits():
    src = "import lxml.etree\nlxml.etree.fromstring(payload)\n"
    findings = XxeRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1


def test_defusedxml_file_suppresses_all_findings():
    """Any defusedxml import suppresses the rule for the whole file (migration mode)."""
    src = (
        "from defusedxml.ElementTree import parse as safe_parse\n"
        "import xml.etree.ElementTree as ET\n"
        "tree = ET.parse('legacy.xml')\n"
        "safe_tree = safe_parse('new.xml')\n"
    )
    assert XxeRule().analyse(make_unit(src), default_ctx()) == []


def test_defusedxml_top_level_import_suppresses():
    src = "import defusedxml\nimport xml.etree.ElementTree as ET\nET.parse('x.xml')\n"
    assert XxeRule().analyse(make_unit(src), default_ctx()) == []


def test_non_xml_parse_call_not_flagged():
    src = "import csv\ncsv.reader('x.csv')\nfoo.parse('y')\n"
    assert XxeRule().analyse(make_unit(src), default_ctx()) == []


def test_unrelated_module_with_parse_method_not_flagged():
    src = "import urllib.parse\nurllib.parse.urlparse('https://x')\n"
    assert XxeRule().analyse(make_unit(src), default_ctx()) == []


def test_carries_security_metadata():
    src = "import xml.etree.ElementTree as ET\nET.parse('x.xml')\n"
    finding = XxeRule().analyse(make_unit(src), default_ctx())[0]
    assert finding.metadata["sinkLabel"] == "xml-parser"
    assert finding.metadata["sourceLabel"] == "xml-input"
