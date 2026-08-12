"""Exercise the Markdown-link sanitizer journey users configure per slot.

The fixtures pair safe render paths with delimiter-preserving attacks so a
configured helper cannot hide the wrong slot. They also pin the explanation
metadata and existing identities a CLI or JSON consumer sees for survivors.
"""

import ast
from typing import Literal

import pytest

from gruffpy.config.analysis_config import AnalysisConfig
from gruffpy.config.rule_settings import RuleSettings
from gruffpy.finding.finding import Finding
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule.context import RuleContext
from gruffpy.rule.security.unsanitized_markdown_interpolation_rule import (
    UnsanitizedMarkdownInterpolationRule,
)
from gruffpy.source.source_file import SourceFile

LinkSyntax = Literal["f-string", "format"]
_LINK_SYNTAXES: tuple[LinkSyntax, ...] = ("f-string", "format")
_CUSTOM_SANITIZERS = {
    "labelSanitizers": ["markdown_label"],
    "urlSanitizers": ["markdown_url"],
}
_LEGACY_FINGERPRINT = "a57fa9e8216f396e"
_LEGACY_LABEL_IDENTITY = "efb98f2e6f5e9b56"
_LEGACY_URL_IDENTITY = "124be12b90c3551a"


def _unit(source: str) -> AnalysisUnit:
    """Parse one user file so the rule sees the same AST as a CLI scan.

    Args:
        source: Complete Python text; empty text represents a clean empty user file.

    Returns:
        Parsed analysis unit whose display path is stable for identity assertions.
    """
    tree = ast.parse(source)
    source_file = SourceFile(absolute_path="/x.py", display_path="x.py", type="python")
    return AnalysisUnit(file=source_file, source=source, tree=tree)


def _context(options: dict[str, object] | None = None) -> RuleContext:
    """Build the rule settings a user gets from defaults plus optional overrides.

    Args:
        options: Public option overrides; ``None`` means generated defaults.

    Returns:
        Scan context with the rule enabled and empty unrelated configuration.
    """
    rule = UnsanitizedMarkdownInterpolationRule()
    definition = rule.definition()
    # No override means the user accepted the generated sanitizer lists.
    user_options = {} if options is None else options
    resolved_options = {**definition.default_options, **user_options}
    return RuleContext(
        project_root="/",
        config=AnalysisConfig(
            rules={
                definition.id: RuleSettings(enabled=True, options=resolved_options),
            }
        ),
    )


def _analyse(source: str, options: dict[str, object] | None = None) -> list[Finding]:
    """Return findings a user would see for one source/configuration pairing.

    Args:
        source: Complete Python source; empty source produces no findings.
        options: Sanitizer overrides; ``None`` keeps public defaults.

    Returns:
        Findings in scan order; an empty list means every detected slot was proved safe.
    """
    return UnsanitizedMarkdownInterpolationRule().analyse(_unit(source), _context(options))


def _link_source(
    syntax: LinkSyntax,
    *,
    label_expression: str,
    url_expression: str,
    setup: str = "",
    module_prelude: str = "",
    parameters: str = "raw_label, raw_url, condition=True",
) -> str:
    """Render equivalent f-string or ``.format()`` user code for paired tests.

    Args:
        syntax: Link construction spelling selected by the user.
        label_expression: Python expression placed in the visible link label.
        url_expression: Python expression placed in the click target.
        setup: Already-indented function statements; empty means direct interpolation.
        module_prelude: Imports or bindings before the function; empty means none.
        parameters: Function signature text; empty means a parameterless render function.

    Returns:
        Complete parseable Python source for the requested user journey.
    """
    # A user with no setup interpolates the expressions directly.
    setup_block = f"{setup}\n" if setup else ""
    # F-string users place the expressions directly between Markdown delimiters.
    if syntax == "f-string":
        return (
            module_prelude
            + "def render("
            + parameters
            + "):\n"
            + setup_block
            + '    return f"""['
            + "{"
            + label_expression
            + "}]({"
            + url_expression
            + '})"""\n'
        )
    return (
        f"{module_prelude}def render({parameters}):\n"
        f"{setup_block}"
        '    return "[{label}]({url})".format('
        f"label={label_expression}, url={url_expression})\n"
    )


def _metadata(finding: Finding) -> dict[str, object]:
    """Project one finding to the user-facing Markdown explanation metadata.

    Args:
        finding: Emitted finding whose metadata is expected to be populated.

    Returns:
        Fresh metadata mapping; empty would mean the rule omitted its explanation.
    """
    return dict(finding.metadata)


@pytest.mark.parametrize(
    ("syntax", "source"),
    (
        pytest.param(
            "f-string",
            (
                "def render(raw_label, raw_url):\n"
                '    return f"[prefix\\x00{raw_label}]({raw_url})"\n'
            ),
            id="f-string",
        ),
        pytest.param(
            "format",
            (
                "def render(raw_label, raw_url):\n"
                '    return "[prefix\\x00{label}]({url})".format('
                "label=raw_label, url=raw_url)\n"
            ),
            id="format",
        ),
    ),
)
def test_static_nul_does_not_collide_with_dynamic_slot_placeholders(
    syntax: LinkSyntax,
    source: str,
) -> None:
    """Keep decoded NUL text distinct from ordered dynamic link slots.

    Args:
        syntax: User link-construction spelling covered by the collision regression.
        source: Parseable link source containing one decoded static NUL.
    """
    findings = _analyse(source)

    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"], syntax


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_raw_slots_keep_existing_message_fingerprint_and_identity(syntax: LinkSyntax) -> None:
    """Raw label and URL findings keep their pre-change identity contract.

    Args:
        syntax: User link-construction spelling covered by the identity control.
    """
    source = _link_source(
        syntax,
        label_expression="raw_label",
        url_expression="raw_url",
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "name",
            "sanitizerResolution": "raw",
        },
        {
            "slot": "url",
            "expressionKind": "name",
            "sanitizerResolution": "raw",
        },
    ]
    assert [finding.fingerprint() for finding in findings] == [
        _LEGACY_FINGERPRINT,
        _LEGACY_FINGERPRINT,
    ]
    assert [finding.stable_identity() for finding in findings] == [
        _LEGACY_LABEL_IDENTITY,
        _LEGACY_URL_IDENTITY,
    ]
    assert findings[0].message.startswith("Markdown link label interpolates a raw value;")
    assert findings[1].message.startswith("Markdown link url interpolates a raw value;")


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_default_attack_pair_flags_html_escape_label_but_accepts_quoted_url(
    syntax: LinkSyntax,
) -> None:
    """HTML escaping remains a deliberate label finding while URL quoting is clean.

    Args:
        syntax: User link-construction spelling receiving the paired attack.
    """
    source = _link_source(
        syntax,
        module_prelude="import html\nimport urllib.parse\n\n",
        label_expression="html.escape(raw_label)",
        url_expression="urllib.parse.quote(raw_url)",
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "call",
            "sanitizerResolution": "unconfigured-call",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
@pytest.mark.parametrize("target", ["urllib.parse.quote", "urllib.parse.quote_plus"])
def test_default_url_sanitizer_is_clean(syntax: LinkSyntax, target: str) -> None:
    """Both generated URL defaults remove a raw click target finding.

    Args:
        syntax: User link-construction spelling under test.
        target: Exact generated URL sanitizer target expected to be trusted.
    """
    source = _link_source(
        syntax,
        module_prelude="import urllib.parse\n\n",
        label_expression='"docs"',
        url_expression=f"{target}(raw_url)",
    )

    assert _analyse(source) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
@pytest.mark.parametrize(
    "url_expression",
    [
        "urllib.parse.quote(raw_url, safe='()')",
        "urllib.parse.quote(raw_url, '()')",
        "urllib.parse.quote(raw_url, safe=allowed_characters)",
        "urllib.parse.quote(raw_url, *quote_arguments)",
        "urllib.parse.quote(raw_url, **quote_options)",
    ],
    ids=["keyword", "positional", "dynamic", "args-splat", "kwargs-splat"],
)
def test_default_url_sanitizer_unsafe_arguments_still_flag(
    syntax: LinkSyntax,
    url_expression: str,
) -> None:
    """A trusted callee cannot hide a delimiter-preserving or uncertain `safe` value.

    Args:
        syntax: User link-construction spelling under attack.
        url_expression: Quote call carrying the unsafe argument shape.
    """
    source = _link_source(
        syntax,
        module_prelude="import urllib.parse\n\n",
        label_expression='"docs"',
        url_expression=url_expression,
        parameters=(
            "raw_label, raw_url, allowed_characters='', quote_arguments=(), "
            "quote_options=None, condition=True"
        ),
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "unsafe-arguments",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_default_url_sanitizer_literal_safe_without_delimiters_is_clean(
    syntax: LinkSyntax,
) -> None:
    """A literal `safe` value remains trusted when it cannot retain link delimiters.

    Args:
        syntax: User link-construction spelling receiving the safe quote call.
    """
    source = _link_source(
        syntax,
        module_prelude="import urllib.parse\n\n",
        label_expression='"docs"',
        url_expression="urllib.parse.quote(raw_url, safe='-_.~')",
    )

    assert _analyse(source) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_direct_configured_sanitizers_are_clean_per_slot(syntax: LinkSyntax) -> None:
    """Exact project helpers clear only the slot the user configured for them.

    Args:
        syntax: User link-construction spelling receiving direct project helpers.
    """
    source = _link_source(
        syntax,
        label_expression="markdown_label(raw_label)",
        url_expression="markdown_url(raw_url)",
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_assigned_configured_sanitizer_results_are_clean(syntax: LinkSyntax) -> None:
    """Users may sanitize before assembling the final Markdown link.

    Args:
        syntax: User link-construction spelling receiving assigned safe values.
    """
    source = _link_source(
        syntax,
        setup=(
            "    escaped_label = markdown_label(raw_label)\n    encoded_url = markdown_url(raw_url)"
        ),
        label_expression="escaped_label",
        url_expression="encoded_url",
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_one_hop_aliases_of_sanitized_values_are_clean(syntax: LinkSyntax) -> None:
    """One readable display-name alias preserves an already-proved safe value.

    Args:
        syntax: User link-construction spelling receiving one-hop aliases.
    """
    source = _link_source(
        syntax,
        setup=(
            "    escaped_label = markdown_label(raw_label)\n"
            "    encoded_url = markdown_url(raw_url)\n"
            "    display_label = escaped_label\n"
            "    click_target = encoded_url"
        ),
        label_expression="display_label",
        url_expression="click_target",
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_configured_sanitizer_or_literal_fallback_is_clean(syntax: LinkSyntax) -> None:
    """Every branch is safe when the user chooses sanitized input or fixed copy.

    Args:
        syntax: User link-construction spelling after the safe branch merge.
    """
    source = _link_source(
        syntax,
        setup=(
            "    if condition:\n"
            "        display_label = markdown_label(raw_label)\n"
            "        click_target = markdown_url(raw_url)\n"
            "    else:\n"
            '        display_label = "docs"\n'
            '        click_target = "https://example.test"'
        ),
        label_expression="display_label",
        url_expression="click_target",
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_raw_or_literal_fallback_is_uncertain(syntax: LinkSyntax) -> None:
    """A raw branch keeps the rendered label unsafe even when its sibling is literal.

    Args:
        syntax: User link-construction spelling after the uncertain branch merge.
    """
    source = _link_source(
        syntax,
        setup=(
            "    if condition:\n"
            "        display_label = raw_label\n"
            "    else:\n"
            '        display_label = "docs"'
        ),
        label_expression="display_label",
        url_expression='"https://example.test"',
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "name",
            "sanitizerResolution": "uncertain-provenance",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_raw_overwrite_kills_assigned_sanitizer_result(syntax: LinkSyntax) -> None:
    """Replacing escaped display text with raw input restores the finding.

    Args:
        syntax: User link-construction spelling receiving the overwritten value.
    """
    source = _link_source(
        syntax,
        setup=("    display_label = markdown_label(raw_label)\n    display_label = raw_label"),
        label_expression="display_label",
        url_expression='"https://example.test"',
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "name",
            "sanitizerResolution": "uncertain-provenance",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_arbitrary_wrappers_remain_findings(syntax: LinkSyntax) -> None:
    """Calls such as `str` and `identity` no longer impersonate sanitizers.

    Args:
        syntax: User link-construction spelling receiving arbitrary wrappers.
    """
    source = _link_source(
        syntax,
        label_expression="str(raw_label)",
        url_expression="identity(raw_url)",
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "call",
            "sanitizerResolution": "unconfigured-call",
        },
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "unconfigured-call",
        },
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_wrong_slot_sanitizers_emit_deterministic_metadata(syntax: LinkSyntax) -> None:
    """A label helper cannot silently authorize a click target, or vice versa.

    Args:
        syntax: User link-construction spelling receiving swapped helpers.
    """
    source = _link_source(
        syntax,
        label_expression="markdown_url(raw_label)",
        url_expression="markdown_label(raw_url)",
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "call",
            "sanitizerResolution": "wrong-slot",
        },
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "wrong-slot",
        },
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_explicit_empty_url_sanitizers_make_default_quote_unconfigured(
    syntax: LinkSyntax,
) -> None:
    """An empty URL list gives users strict mode in which no call is trusted.

    Args:
        syntax: User link-construction spelling evaluated under URL strict mode.
    """
    source = _link_source(
        syntax,
        module_prelude="import urllib.parse\n\n",
        label_expression='"docs"',
        url_expression="urllib.parse.quote(raw_url)",
    )

    findings = _analyse(source, {"urlSanitizers": []})

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "unconfigured-call",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_html_escape_can_be_an_explicit_label_opt_in(syntax: LinkSyntax) -> None:
    """Projects may knowingly accept HTML escaping for their rendering context.

    Args:
        syntax: User link-construction spelling receiving the explicit opt-in.
    """
    source = _link_source(
        syntax,
        module_prelude="import html\n\n",
        label_expression="html.escape(raw_label)",
        url_expression='"https://example.test"',
    )

    findings = _analyse(source, {"labelSanitizers": ["html.escape"]})

    assert findings == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_custom_url_sanitizer_is_not_subject_to_quote_safe_argument_rules(
    syntax: LinkSyntax,
) -> None:
    """Only built-in quote defaults receive the Python-specific `safe` gate.

    Args:
        syntax: User link-construction spelling receiving the custom helper.
    """
    source = _link_source(
        syntax,
        label_expression='"docs"',
        url_expression="markdown_url(raw_url, safe='()')",
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert findings == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
@pytest.mark.parametrize(
    ("module_prelude", "url_expression"),
    [
        ("from urllib.parse import quote\n\n", "quote(raw_url)"),
        ("from urllib.parse import quote as encode_url\n\n", "encode_url(raw_url)"),
        ("import urllib.parse as url_tools\n\n", "url_tools.quote(raw_url)"),
    ],
    ids=["from-import", "from-import-alias", "module-alias"],
)
def test_approved_import_bindings_match_default_url_sanitizer(
    syntax: LinkSyntax,
    module_prelude: str,
    url_expression: str,
) -> None:
    """Same-file import syntax recognizes the dominant quoted-URL spellings.

    Args:
        syntax: User link-construction spelling receiving the imported helper.
        module_prelude: Exact import/from-import statement establishing the binding.
        url_expression: Local or aliased call expected to resolve canonically.
    """
    source = _link_source(
        syntax,
        module_prelude=module_prelude,
        label_expression='"docs"',
        url_expression=url_expression,
    )

    assert _analyse(source) == []


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_rebound_import_alias_loses_sanitizer_trust(syntax: LinkSyntax) -> None:
    """A user assignment after import prevents a stale alias from hiding raw input.

    Args:
        syntax: User link-construction spelling after local alias rebinding.
    """
    source = _link_source(
        syntax,
        module_prelude="from urllib.parse import quote as encode_url\n\n",
        setup="    encode_url = identity",
        label_expression='"docs"',
        url_expression="encode_url(raw_url)",
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "shadowed-target",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_module_rebound_import_alias_loses_sanitizer_trust(syntax: LinkSyntax) -> None:
    """A module assignment before rendering invalidates the imported URL helper.

    Args:
        syntax: User link-construction spelling after module alias rebinding.
    """
    source = _link_source(
        syntax,
        module_prelude=("from urllib.parse import quote as encode_url\nencode_url = identity\n\n"),
        label_expression='"docs"',
        url_expression="encode_url(raw_url)",
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "shadowed-target",
        }
    ]


@pytest.mark.parametrize("syntax", _LINK_SYNTAXES)
def test_parameter_shadowing_loses_imported_sanitizer_trust(syntax: LinkSyntax) -> None:
    """A callback parameter named `quote` is user code, not the imported sanitizer.

    Args:
        syntax: User link-construction spelling whose parameter shadows the import.
    """
    source = _link_source(
        syntax,
        module_prelude="from urllib.parse import quote\n\n",
        parameters="raw_label, raw_url, quote, condition=True",
        label_expression='"docs"',
        url_expression="quote(raw_url)",
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "call",
            "sanitizerResolution": "shadowed-target",
        }
    ]


@pytest.mark.parametrize(
    "method_return",
    [
        '        return f"[docs]({quote(raw_url)})"\n',
        '        return "[docs]({url})".format(url=quote(raw_url))\n',
    ],
    ids=_LINK_SYNTAXES,
)
def test_class_method_retains_prior_module_import_binding(method_return: str) -> None:
    """A module import remains visible when a class method starts fresh.

    Args:
        method_return: F-string or `.format()` return line inside the method.
    """
    source = (
        "from urllib.parse import quote\n"
        "class Renderer:\n"
        "    def render(self, raw_url):\n" + method_return
    )

    assert _analyse(source) == []


@pytest.mark.parametrize(
    "lambda_expression",
    [
        'lambda encoded_url: f"[docs]({encoded_url})"',
        'lambda encoded_url: "[docs]({url})".format(url=encoded_url)',
    ],
    ids=_LINK_SYNTAXES,
)
def test_lambda_parameter_starts_with_fresh_value_provenance(
    lambda_expression: str,
) -> None:
    """A lambda parameter cannot inherit a safe outer value with the same name.

    Args:
        lambda_expression: F-string or `.format()` lambda body using its raw parameter.
    """
    source = (
        "from urllib.parse import quote\n"
        "def render(raw_url):\n"
        "    encoded_url = quote(raw_url)\n"
        f"    formatter = {lambda_expression}\n"
        "    return formatter(raw_url)\n"
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "name",
            "sanitizerResolution": "raw",
        }
    ]


@pytest.mark.parametrize(
    "lambda_expression",
    [
        'lambda value: f"[docs]({quote(value)})"',
        'lambda value: "[docs]({url})".format(url=quote(value))',
    ],
    ids=_LINK_SYNTAXES,
)
def test_lambda_body_retains_imported_callable_proof(lambda_expression: str) -> None:
    """Fresh lambda values do not discard an imported sanitizer binding.

    Args:
        lambda_expression: F-string or `.format()` lambda body calling the import.
    """
    source = (
        "from urllib.parse import quote\n"
        "def render(raw_url):\n"
        f"    formatter = {lambda_expression}\n"
        "    return formatter(raw_url)\n"
    )

    assert _analyse(source) == []


@pytest.mark.parametrize(
    "comprehension_expression",
    [
        '[f"[docs]({safe})" for safe in raw_urls]',
        '["[docs]({url})".format(url=safe) for safe in raw_urls]',
    ],
    ids=_LINK_SYNTAXES,
)
def test_comprehension_target_shadows_outer_sanitized_value(
    comprehension_expression: str,
) -> None:
    """A comprehension target cannot inherit a same-named outer proof.

    Args:
        comprehension_expression: F-string or `.format()` link built from the target.
    """
    source = (
        "from urllib.parse import quote\n"
        "def render(raw_url, raw_urls):\n"
        "    safe = quote(raw_url)\n"
        f"    return {comprehension_expression}\n"
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "name",
            "sanitizerResolution": "uncertain-provenance",
        }
    ]


@pytest.mark.parametrize(
    "comprehension_expression",
    [
        '[f"[docs]({safe})" for item in raw_urls]',
        '["[docs]({url})".format(url=safe) for item in raw_urls]',
    ],
    ids=_LINK_SYNTAXES,
)
def test_comprehension_body_retains_unshadowed_outer_sanitized_value(
    comprehension_expression: str,
) -> None:
    """A comprehension may capture a safe outer value under another target name.

    Args:
        comprehension_expression: F-string or `.format()` link capturing the outer value.
    """
    source = (
        "from urllib.parse import quote\n"
        "def render(raw_url, raw_urls):\n"
        "    safe = quote(raw_url)\n"
        f"    return {comprehension_expression}\n"
    )

    assert _analyse(source) == []


@pytest.mark.parametrize(
    "nested_return",
    [
        '        return f"[docs]({encoded_url})"\n',
        '        return "[docs]({url})".format(url=encoded_url)\n',
    ],
    ids=_LINK_SYNTAXES,
)
def test_nested_function_starts_with_fresh_value_provenance(nested_return: str) -> None:
    """An inner renderer cannot inherit an outer function's local safety proof.

    Args:
        nested_return: F-string or `.format()` return line inside the fresh scope.
    """
    source = (
        "def outer(raw_url):\n"
        "    encoded_url = markdown_url(raw_url)\n"
        "    def render():\n" + nested_return + "    return render()\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "url",
            "expressionKind": "name",
            "sanitizerResolution": "raw",
        }
    ]


@pytest.mark.parametrize(
    ("label_expression", "expression_kind", "sanitizer_resolution"),
    [
        ("user.title", "attribute", "raw"),
        ('payload["title"]', "subscript", "raw"),
        ('raw_label if condition else "docs"', "conditional", "uncertain-provenance"),
        ("raw_label + suffix", "other", "raw"),
    ],
    ids=["attribute", "subscript", "conditional", "other"],
)
def test_expression_kind_metadata_explains_raw_shapes(
    label_expression: str,
    expression_kind: str,
    sanitizer_resolution: str,
) -> None:
    """JSON consumers receive a bounded expression label for remediation routing.

    Args:
        label_expression: Raw source shape placed in the visible link label.
        expression_kind: Stable syntax enum expected in JSON metadata.
        sanitizer_resolution: Stable proof-failure enum expected in JSON metadata.
    """
    source = _link_source(
        "f-string",
        parameters="raw_label, raw_url, user, payload, suffix, condition=True",
        label_expression=label_expression,
        url_expression='"https://example.test"',
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": expression_kind,
            "sanitizerResolution": sanitizer_resolution,
        }
    ]


def test_extracted_consumer_memory_index_shape_keeps_both_attack_controls() -> None:
    """Keep the real memory-index label and filename shape visible as two findings."""
    source = (
        "def add_memory_index_entry(first_line, filename, description):\n"
        "    new_index_entries = []\n"
        '    new_index_entries.append(f"- [{first_line[:60]}]({filename}) — '
        '{description[:80]}")\n'
    )

    findings = _analyse(source)

    assert [_metadata(finding) for finding in findings] == [
        {
            "slot": "label",
            "expressionKind": "subscript",
            "sanitizerResolution": "raw",
        },
        {
            "slot": "url",
            "expressionKind": "name",
            "sanitizerResolution": "raw",
        },
    ]


def test_definition_exposes_slot_asymmetric_sanitizer_defaults() -> None:
    """Generated config shows strict labels and the two vetted URL encoders."""
    definition = UnsanitizedMarkdownInterpolationRule().definition()

    assert definition.default_options == {
        "labelSanitizers": [],
        "urlSanitizers": ["urllib.parse.quote", "urllib.parse.quote_plus"],
    }
    assert definition.default_severity.value == "advisory"
    assert definition.confidence.value == "medium"
    assert definition.pillar.value == "security"
    assert definition.default_enabled is True


def test_match_case_body_keeps_a_configured_url_sanitizer_proved() -> None:
    """A helper called inside a `case` body still proves the URL the user clicks."""
    source = (
        "def render(mode, raw_url):\n"
        "    match mode:\n"
        "        case 'link':\n"
        "            safe_url = markdown_url(raw_url)\n"
        "            return f'[text]({safe_url})'\n"
        "    return ''\n"
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


def test_match_case_rebinding_a_sanitizer_removes_its_proof() -> None:
    """Reassigning the helper in one `case` leaves every later link unproved."""
    source = (
        "def render(mode, raw_url):\n"
        "    match mode:\n"
        "        case 'raw':\n"
        "            markdown_url = str\n"
        "    return f'[text]({markdown_url(raw_url)})'\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["sanitizerResolution"] for finding in findings] == ["shadowed-target"]


def test_match_capture_name_is_never_a_proved_value() -> None:
    """A value captured out of the subject is raw, so the user still sees a finding."""
    source = (
        "def render(payload):\n"
        "    match payload:\n"
        "        case {'url': captured_url}:\n"
        "            return f'[text]({captured_url})'\n"
        "    return ''\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["sanitizerResolution"] for finding in findings] == ["raw"]


def test_except_star_handler_proves_the_same_url_as_a_plain_handler() -> None:
    """An `except*` group merges like `except`, so the safe URL stays quiet."""
    source = (
        "def render(raw_url):\n"
        "    try:\n"
        "        safe_url = markdown_url(raw_url)\n"
        "    except* ValueError:\n"
        "        safe_url = ''\n"
        "    return f'[text]({safe_url})'\n"
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


_LOOP_HEADERS = (
    pytest.param("def render", "    for item in items:", id="for"),
    pytest.param("async def render", "    async for item in items:", id="async-for"),
    pytest.param("def render", "    while items:", id="while"),
)


@pytest.mark.parametrize(("declaration", "loop_header"), _LOOP_HEADERS)
def test_loop_carried_rebinding_is_not_proved_safe(declaration: str, loop_header: str) -> None:
    """A body that rebinds a proved name to a raw value is unsafe from the second pass.

    Args:
        declaration: `def` or `async def` matching the loop form under test.
        loop_header: Loop statement the user wrote around the rendered link.
    """
    source = (
        f"{declaration}(raw_url, items):\n"
        "    safe_url = markdown_url(raw_url)\n"
        f"{loop_header}\n"
        "        rendered = f'[text]({safe_url})'\n"
        "        safe_url = raw_url\n"
        "    return rendered\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["slot"] for finding in findings] == ["url"]


@pytest.mark.parametrize(("declaration", "loop_header"), _LOOP_HEADERS)
def test_loop_body_that_proves_before_rendering_stays_quiet(
    declaration: str,
    loop_header: str,
) -> None:
    """Keep a value the body sanitizes before every render out of findings.

    Args:
        declaration: `def` or `async def` matching the loop form under test.
        loop_header: Loop statement the user wrote around the rendered link.
    """
    source = (
        f"{declaration}(raw_url, items):\n"
        f"{loop_header}\n"
        "        safe_url = markdown_url(raw_url)\n"
        "        rendered = f'[text]({safe_url})'\n"
        "    return rendered\n"
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


def test_loop_body_without_a_rebinding_keeps_its_pre_loop_proof() -> None:
    """Keep a proof established before the loop when the body never rebinds it."""
    source = (
        "def render(raw_url, items):\n"
        "    safe_url = markdown_url(raw_url)\n"
        "    for item in items:\n"
        "        rendered = f'[text]({safe_url})'\n"
        "    return rendered\n"
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


def test_inner_loop_render_sees_an_outer_loop_rebinding() -> None:
    """Invalidate across nested loops, where the rebinding sits in the outer body."""
    source = (
        "def render(raw_url, rows, cols):\n"
        "    safe_url = markdown_url(raw_url)\n"
        "    for row in rows:\n"
        "        for col in cols:\n"
        "            rendered = f'[text]({safe_url})'\n"
        "        safe_url = raw_url\n"
        "    return rendered\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_context_manager_target_rebinding_inside_a_loop_is_not_proved_safe() -> None:
    """Treat a `with ... as name` rebinding like an assignment for the next pass."""
    source = (
        "def render(raw_url, items, opened):\n"
        "    safe_url = markdown_url(raw_url)\n"
        "    for item in items:\n"
        "        rendered = f'[text]({safe_url})'\n"
        "        with opened as safe_url:\n"
        "            pass\n"
        "    return rendered\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_sanitizer_rebound_inside_a_loop_stops_proving_later_passes() -> None:
    """A body that reassigns the configured sanitizer name cannot prove its own render."""
    source = (
        "def render(raw_url, items, identity):\n"
        "    for item in items:\n"
        "        rendered = f'[text]({markdown_url(raw_url)})'\n"
        "        markdown_url = identity\n"
        "    return rendered\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_sanitizer_rebound_by_a_match_case_inside_a_loop_stops_proving_later_passes() -> None:
    """A `match` case that captures the sanitizer name invalidates a loop-carried proof.

    A later pass renders before the case runs, so the captured runtime value -
    not the configured helper - is what a subsequent iteration would call.
    """
    source = (
        "def render(raw_url, items):\n"
        "    for item in items:\n"
        "        rendered = f'[text]({markdown_url(raw_url)})'\n"
        "        match item:\n"
        "            case {'handler': markdown_url}:\n"
        "                pass\n"
        "    return rendered\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_format_template_with_padding_placeholder_characters_does_not_crash() -> None:
    """Static NUL padding around a `.format()` field must not overrun the value list.

    The placeholder token is derived from the field-stripped static text, so a
    literal NUL adjacent to a field cannot merge with it and be counted twice.
    """
    source = 'link = "[\\x00{label}\\x00]({url})".format(label=raw_label, url=raw_url)\n'

    findings = _analyse(source)

    assert [finding.metadata["slot"] for finding in findings] == ["label", "url"]


def test_walrus_rebinding_a_proved_value_stops_proving_the_render() -> None:
    """A ``:=`` assignment destroys an earlier sanitizer proof like any other rebind."""
    source = (
        "def render(raw_url):\n"
        "    safe_url = markdown_url(raw_url)\n"
        "    if (safe_url := raw_url):\n"
        "        pass\n"
        "    return f'[text]({safe_url})'\n"
    )

    findings = _analyse(source, _CUSTOM_SANITIZERS)

    assert [finding.metadata["slot"] for finding in findings] == ["url"]


def test_walrus_proving_a_value_is_trusted_at_a_later_render() -> None:
    """A ``:=`` assignment can also establish the proof a later render relies on."""
    source = (
        "def render(raw_url):\n"
        "    if (safe_url := markdown_url(raw_url)):\n"
        "        pass\n"
        "    return f'[text]({safe_url})'\n"
    )

    assert _analyse(source, _CUSTOM_SANITIZERS) == []


def test_label_sanitizer_preserving_link_delimiters_is_not_trusted() -> None:
    """A configured quote helper that keeps `]`, `(`, `)` cannot prove a safe label."""
    source = (
        "import urllib.parse\n"
        "def render(raw_label, raw_url):\n"
        '    return f\'[{urllib.parse.quote(raw_label, safe="]()")}]'
        "({urllib.parse.quote(raw_url)})'\n"
    )

    findings = _analyse(
        source,
        {
            "labelSanitizers": ["urllib.parse.quote"],
            "urlSanitizers": ["urllib.parse.quote"],
        },
    )

    assert [finding.metadata["slot"] for finding in findings] == ["label"]
    assert findings[0].metadata["sanitizerResolution"] == "unsafe-arguments"
