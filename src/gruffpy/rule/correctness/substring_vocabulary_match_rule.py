"""``correctness.substring-vocabulary-match`` - substring scans of a vocabulary over free text.

Detects membership scanning of a module-level constant collection of string
literals over parameter-derived free text via substring containment:

- ``any(term in text for term in VOCAB)``
- the loop form ``for term in VOCAB: if term in text: ...``

Substring containment routes "coffee" to a "fee" vocabulary entry,
"information" to "form", and "profile" to "file" - verified misroutes in
production copy-routing. The fix is word-boundary or token matching.

False-positive guards (all must pass before a finding is emitted):

- ``VOCAB`` resolves to a module-level tuple/list/set/frozenset of string
  literals (directly or wrapped in a ``tuple``/``list``/``set``/``frozenset``
  call).
- ``text`` is a parameter of the enclosing function, or a local assigned once
  from a parameter through a pure case/whitespace chain (``lower``,
  ``casefold``, ``strip``, ``lstrip``, ``rstrip``, ``upper``) - call-derived
  or collection-typed targets (e.g. ``re.findall`` token lists) never match.
- the text name or its source parameter carries a free-text token
  (``message``, ``text``, ``query``, ``prompt``, ``body``, ...) - identifier
  and marker scans such as ``marker in normalized`` are intentional substring
  checks, not copy routing.
- vocabularies whose every entry contains a space are skipped (phrase lists
  substring-match far more precisely than single words).
"""

import ast

from gruffpy.finding.confidence import Confidence
from gruffpy.finding.finding import Finding
from gruffpy.finding.pillar import Pillar
from gruffpy.finding.rule_tier import RuleTier
from gruffpy.finding.severity import Severity
from gruffpy.parser.analysis_unit import AnalysisUnit
from gruffpy.rule._ast_scope import walk_function_scope
from gruffpy.rule.context import RuleContext
from gruffpy.rule.definition import RuleDefinition
from gruffpy.rule.rule import Rule

_FREE_TEXT_TOKENS: frozenset[str] = frozenset(
    {
        "body",
        "comment",
        "content",
        "description",
        "input",
        "message",
        "msg",
        "prompt",
        "query",
        "question",
        "sentence",
        "text",
        "title",
        "transcript",
        "utterance",
    }
)
_TEXT_CHAIN_METHODS: frozenset[str] = frozenset(
    {"lower", "casefold", "strip", "lstrip", "rstrip", "upper"}
)
_COLLECTION_WRAPPERS: frozenset[str] = frozenset({"frozenset", "list", "set", "tuple"})
_REMEDIATION = (
    "Match whole words instead of substrings: tokenise the text "
    '(re.findall(r"\\w+", text.lower())) and test set membership, or compile '
    'a word-boundary alternation (r"\\b(?:term1|term2)\\b").'
)


class SubstringVocabularyMatchRule(Rule):
    """Detect constant-vocabulary substring scans over parameter-derived free text."""

    ID = "correctness.substring-vocabulary-match"

    def definition(self) -> RuleDefinition:
        """Describe the substring-vocabulary-match rule as a medium-confidence advisory.

        Medium confidence: the shape match is exact, but whether substring
        semantics are a bug depends on the vocabulary's intent, so the rule
        is confined to free-text-named targets derived from parameters.

        Returns:
            Definition for the substring-vocabulary-match rule under the
            correctness pillar.
        """
        return RuleDefinition(
            id=self.ID,
            name="Substring vocabulary match",
            pillar=Pillar.CORRECTNESS,
            tier=RuleTier.V01,
            default_severity=Severity.ADVISORY,
            confidence=Confidence.MEDIUM,
        )

    def analyse(self, unit: AnalysisUnit, context: RuleContext) -> list[Finding]:
        """Flag substring vocabulary scans over parameter-derived free text.

        Args:
            unit: Parsed source file to inspect.
            context: Rule execution context (unused - no thresholds).

        Returns:
            One finding per matching scan site.
        """
        if not isinstance(unit.tree, ast.Module) or " in " not in unit.source:
            return []
        vocabularies = _module_string_vocabularies(unit.tree)
        if not vocabularies:
            return []
        definition = self.definition()
        findings: list[Finding] = []
        for function in (
            node
            for node in ast.walk(unit.tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            findings.extend(_scan_function(definition, unit, function, vocabularies))
        return findings


def _module_string_vocabularies(tree: ast.Module) -> dict[str, list[str]]:
    """Collect module-level constants holding only string literals."""
    vocabularies: dict[str, list[str]] = {}
    for node in tree.body:
        target = _single_assign_target(node)
        if target is None or not isinstance(node, ast.Assign):
            continue
        literals = _string_literals(node.value)
        if literals is not None:
            vocabularies[target] = literals
    return vocabularies


def _single_assign_target(node: ast.stmt) -> str | None:
    if (
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ):
        return node.targets[0].id
    return None


def _string_literals(value: ast.expr) -> list[str] | None:
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in _COLLECTION_WRAPPERS
        and len(value.args) == 1
        and not value.keywords
    ):
        value = value.args[0]
    if not isinstance(value, (ast.List, ast.Set, ast.Tuple)):
        return None
    literals: list[str] = []
    for element in value.elts:
        if not (isinstance(element, ast.Constant) and isinstance(element.value, str)):
            return None
        literals.append(element.value)
    return literals


def _scan_function(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    vocabularies: dict[str, list[str]],
) -> list[Finding]:
    parameters = {
        parameter.arg
        for parameter in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }
    text_sources = _parameter_text_sources(function, parameters)
    findings: list[Finding] = []
    for node in walk_function_scope(function):
        site = _vocabulary_scan_site(node)
        if site is None:
            continue
        vocabulary_name, text_name, scan_node = site
        vocabulary = vocabularies.get(vocabulary_name)
        if vocabulary is None or not vocabulary:
            continue
        if all(" " in entry for entry in vocabulary):
            continue
        source_name = text_sources.get(text_name)
        if source_name is None:
            continue
        if not _has_free_text_token(text_name) and not _has_free_text_token(source_name):
            continue
        findings.append(_build_finding(definition, unit, scan_node, vocabulary_name, text_name))
    return findings


def _parameter_text_sources(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parameters: set[str],
) -> dict[str, str]:
    """Map text-candidate locals to the parameter they derive from.

    A parameter maps to itself; a local qualifies only when assigned exactly
    once from a parameter through a pure case/whitespace method chain, so
    call-derived strings and tokenised collections never qualify. A name
    reassigned from any other expression (e.g. ``text = text.split()``) is
    dropped even when it is a parameter, because it no longer holds the
    free-text string the scan would match against.
    """
    sources: dict[str, str] = {name: name for name in parameters}
    assigned_counts: dict[str, int] = {}
    clobbered: set[str] = set()
    for node in walk_function_scope(function):
        if not isinstance(node, ast.Assign):
            continue
        target = _single_assign_target(node)
        if target is None:
            continue
        assigned_counts[target] = assigned_counts.get(target, 0) + 1
        root = _case_chain_root(node.value)
        if root is not None and root in parameters:
            sources[target] = root
        else:
            clobbered.add(target)
    return {
        name: source
        for name, source in sources.items()
        if (assigned_counts.get(name, 0) <= 1 or name in parameters) and name not in clobbered
    }


def _case_chain_root(value: ast.expr) -> str | None:
    while (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr in _TEXT_CHAIN_METHODS
        and not value.args
        and not value.keywords
    ):
        value = value.func.value
    if isinstance(value, ast.Name):
        return value.id
    return None


def _vocabulary_scan_site(node: ast.AST) -> tuple[str, str, ast.AST] | None:
    """Return ``(vocabulary, text, node)`` for an any()-scan or loop-scan site."""
    if isinstance(node, ast.Call):
        return _any_scan_site(node)
    if isinstance(node, ast.For):
        return _loop_scan_site(node)
    return None


def _any_scan_site(call: ast.Call) -> tuple[str, str, ast.AST] | None:
    if not (isinstance(call.func, ast.Name) and call.func.id == "any"):
        return None
    if len(call.args) != 1 or not isinstance(call.args[0], ast.GeneratorExp):
        return None
    generator = call.args[0]
    if len(generator.generators) != 1:
        return None
    comprehension = generator.generators[0]
    if not (
        isinstance(comprehension.target, ast.Name) and isinstance(comprehension.iter, ast.Name)
    ):
        return None
    text_name = _containment_text(generator.elt, comprehension.target.id)
    if text_name is None:
        return None
    return comprehension.iter.id, text_name, call


def _loop_scan_site(loop: ast.For) -> tuple[str, str, ast.AST] | None:
    if not (isinstance(loop.target, ast.Name) and isinstance(loop.iter, ast.Name)):
        return None
    for statement in loop.body:
        if not isinstance(statement, ast.If):
            continue
        text_name = _containment_text(statement.test, loop.target.id)
        if text_name is not None:
            return loop.iter.id, text_name, statement
    return None


def _containment_text(expression: ast.expr, term_name: str) -> str | None:
    """Return the containment target name for ``<term> in <text>`` comparisons."""
    if not (isinstance(expression, ast.Compare) and len(expression.ops) == 1):
        return None
    if not isinstance(expression.ops[0], ast.In):
        return None
    if not (isinstance(expression.left, ast.Name) and expression.left.id == term_name):
        return None
    comparator = expression.comparators[0]
    if isinstance(comparator, ast.Name):
        return comparator.id
    return None


def _has_free_text_token(name: str) -> bool:
    return any(token in _FREE_TEXT_TOKENS for token in name.lower().split("_"))


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    vocabulary_name: str,
    text_name: str,
) -> Finding:
    return Finding(
        rule_id=definition.id,
        message=(
            f"Substring scan of `{vocabulary_name}` over `{text_name}` matches inside "
            'words ("fee" routes "coffee", "form" routes "information"); the '
            "comparison needs word-boundary or token matching."
        ),
        file_path=unit.file.display_path,
        line=getattr(node, "lineno", 1),
        severity=definition.default_severity,
        pillar=definition.pillar,
        tier=definition.tier,
        confidence=definition.confidence,
        end_line=getattr(node, "end_lineno", None),
        remediation=_REMEDIATION,
        secondary_pillars=definition.secondary_pillars,
        metadata={
            "vocabulary": vocabulary_name,
            "text": text_name,
        },
    )
