from gruffpy.rule.sensitive_data.phi_pattern_rule import PhiPatternRule
from tests.unit.rule.sensitive_data._helpers import default_ctx, make_unit


def test_ssn_emits():
    ssn = "412" + "-78-" + "3491"
    src = f"patient_ssn = {ssn!r}\n"
    findings = PhiPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "ssn"


def test_ssn_placeholder_skipped():
    src = "ssn = '123-45-6789'\n"
    assert PhiPatternRule().analyse(make_unit(src), default_ctx()) == []


def test_mrn_emits():
    mrn = "MRN: " + "482" + "7193"
    src = f"patient = {mrn!r}\n"
    findings = PhiPatternRule().analyse(make_unit(src), default_ctx())
    assert len(findings) == 1
    assert findings[0].metadata["kind"] == "mrn"


def test_random_digits_not_flagged():
    src = "x = 12345\n"
    assert PhiPatternRule().analyse(make_unit(src), default_ctx()) == []
