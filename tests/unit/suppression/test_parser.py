from gruffpy.suppression.parser import parse_suppressions


def test_disable_same_line_suppression() -> None:
    parsed = parse_suppressions("import os  # gruff: disable=waste.unused-import\n")

    assert parsed.disabled_on_line(1) == frozenset({"waste.unused-import"})
    assert parsed.diagnostics == ()


def test_disable_next_targets_next_physical_line_only() -> None:
    parsed = parse_suppressions(
        "# gruff: disable-next=security.dangerous-function-call\neval('payload')\neval('payload')\n"
    )

    assert parsed.disabled_on_line(1) == frozenset()
    assert parsed.disabled_on_line(2) == frozenset({"security.dangerous-function-call"})
    assert parsed.disabled_on_line(3) == frozenset()


def test_disable_file_is_file_local() -> None:
    parsed = parse_suppressions("# gruff: disable-file=size.file-length\nx = 1\n")

    assert parsed.file_disabled_rule_ids == frozenset({"size.file-length"})


def test_multiple_ids_and_whitespace_variants() -> None:
    parsed = parse_suppressions(
        "# gruff:   disable = size.file-length, security.dangerous-function-call \n"
    )

    assert parsed.disabled_on_line(1) == frozenset(
        {"size.file-length", "security.dangerous-function-call"}
    )


def test_string_literals_are_not_parsed_as_suppression_comments() -> None:
    parsed = parse_suppressions('text = "# gruff: disable-file=size.file-length"\n')

    assert parsed.file_disabled_rule_ids == frozenset()
    assert parsed.line_disabled_rule_ids == {}
    assert parsed.next_line_disabled_rule_ids == {}


def test_malformed_suppression_produces_diagnostic_and_no_suppression() -> None:
    parsed = parse_suppressions("# gruff: disable=\n")

    assert parsed.disabled_on_line(1) == frozenset()
    assert len(parsed.diagnostics) == 1
    assert parsed.diagnostics[0].type == "suppression-parse-error"
    assert parsed.diagnostics[0].line == 1


def test_unknown_rule_id_produces_diagnostic_and_does_not_suppress() -> None:
    parsed = parse_suppressions(
        "# gruff: disable=unknown.rule, size.file-length\n",
        known_rule_ids=frozenset({"size.file-length"}),
    )

    assert parsed.disabled_on_line(1) == frozenset({"size.file-length"})
    assert len(parsed.diagnostics) == 1
    assert parsed.diagnostics[0].type == "suppression-unknown-rule"
    assert parsed.diagnostics[0].rule_id == "unknown.rule"


def test_unknown_directive_produces_diagnostic() -> None:
    parsed = parse_suppressions("# gruff: disable-block=size.file-length\n")

    assert parsed.disabled_on_line(1) == frozenset()
    assert len(parsed.diagnostics) == 1
    assert parsed.diagnostics[0].type == "suppression-parse-error"
