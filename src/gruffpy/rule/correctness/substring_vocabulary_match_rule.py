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
  targets, collection-typed locals (e.g. ``re.findall`` token lists), and
  parameters annotated as a ``dict``/``set``/``list``/``Mapping`` collection
  (where ``in`` is key membership, not substring) never match.
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
_TEXT_CHAIN_METHODS: frozenset[str] = frozenset({"lower", "casefold", "strip", "lstrip", "rstrip", "upper"})
_COLLECTION_WRAPPERS: frozenset[str] = frozenset({"frozenset", "list", "set", "tuple"})
# Head types whose ``k in value`` is membership, not substring containment. A
# parameter annotated as one of these never holds the free-text string the scan
# would misroute, even when its name carries a free-text token (``input``...).
_COLLECTION_ANNOTATIONS: frozenset[str] = frozenset(
    {
        "AbstractSet",
        "ChainMap",
        "Collection",
        "Container",
        "Counter",
        "DefaultDict",
        "Dict",
        "FrozenSet",
        "Iterable",
        "Iterator",
        "List",
        "Mapping",
        "MutableMapping",
        "MutableSequence",
        "MutableSet",
        "OrderedDict",
        "Sequence",
        "Set",
        "Tuple",
        "defaultdict",
        "dict",
        "frozenset",
        "list",
        "set",
        "tuple",
    }
)
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
        for function in (node for node in ast.walk(unit.tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            findings.extend(_scan_function(definition, unit, function, vocabularies))
        return findings


def _module_string_vocabularies(tree: ast.Module) -> dict[str, list[str]]:
    """Collect module-level constants holding only string literals.

    Args:
        tree: Parsed module whose direct body statements are inspected; assignments nested in functions, classes or if, try and with blocks are not
            considered.

    Returns:
        Mapping from each top-level name whose single-target assignment holds a list, set or tuple display of string literals, optionally wrapped in
        one tuple, list, set or frozenset call, to its entries in source order. A later qualifying assignment to the same name replaces the earlier
        entries, a later non-qualifying one leaves them in place, and an empty display, bare or wrapped as in frozenset(()), maps to an empty list,
        while a zero-argument call such as frozenset() does not qualify. Empty when no top-level assignment qualifies.
    """
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
    """Return the name bound by an assignment statement whose only target is a bare name.

    Args:
        node: Statement to inspect, either a module-level statement or an assignment found in a function scope.

    Returns:
        The bound name, or None when the statement is not a plain assignment, chains several targets (a = b = ...), or targets an attribute, subscript
        or unpacking pattern. Annotated and augmented assignments also return None.
    """
    if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
        return node.targets[0].id
    return None


def _string_literals(value: ast.expr) -> list[str] | None:
    """Read the entries of a list, set or tuple display that holds only string literals.

    A call to tuple, list, set or frozenset with exactly one positional argument and no keywords is unwrapped once before the display is checked.

    Args:
        value: Right-hand side of a top-level assignment that may hold a vocabulary.

    Returns:
        The string entries in source order, or an empty list for an empty display. None when the value, after unwrapping, is not a list, set or tuple
        display, or when any element is not a string constant.
    """
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
    """Report each vocabulary scan in one function's own scope that runs over parameter-derived free text.

    Only positional-only, regular and keyword-only parameters without a collection annotation count as source parameters; *args and **kwargs are
    ignored. A scan site is reported only when its iterable names a non-empty module vocabulary with at least one entry that has no space, its text
    name maps to a source parameter, and either the text name or that parameter carries a free-text token.

    The walk stops at nested functions, classes and lambdas. Nested functions and methods get their own pass from analyse, but statements directly in
    a nested class body and lambda bodies are not scanned at all.

    Args:
        definition: Rule definition whose id, severity, pillar, tier, confidence and secondary pillars are copied into each finding.
        unit: Analysis unit that supplies the file path for each finding.
        function: Function whose parameters and own-scope body are scanned.
        vocabularies: Module-level vocabulary names mapped to their string entries, as collected from the module's top-level assignments.

    Returns:
        One finding per qualifying scan site in the function's own scope; empty when none qualifies.
    """
    parameters = {
        parameter.arg
        for parameter in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
        if not _is_collection_annotated(parameter.annotation)
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
    """Map text-candidate names to the parameter they derive from.

    A parameter maps to itself. A local qualifies only when exactly one plain single-target assignment in the function's own scope binds it, and that
    assignment's value is a parameter, either bare or under a chain of argument-free lower, casefold, strip, lstrip, rstrip or upper calls, so
    call-derived strings and tokenised collections never qualify. A name rebound by such an assignment from any other expression (e.g. text =
    text.split()) is dropped even when it is a parameter, because it no longer holds the free-text string the scan would match against. A parameter
    rebound only through such chains stays mapped, to the chain's root, which is itself unless the chain starts at another parameter.

    Annotated, augmented, chained, unpacking, loop, with and walrus bindings are not counted, so a local bound only that way is never mapped and a
    parameter rebound that way stays mapped.

    Args:
        function: Function whose own-scope assignments are inspected; assignments in nested functions, classes and lambdas are not.
        parameters: The function's parameter names that are not collection-annotated; each starts mapped to itself, and only these can be the root a
            name derives from.

    Returns:
        Mapping from each qualifying parameter or local to the parameter it derives from; a name missing from the mapping cannot be the text of a
        reported scan.
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
    return {name: source for name, source in sources.items() if (assigned_counts.get(name, 0) <= 1 or name in parameters) and name not in clobbered}


def _case_chain_root(value: ast.expr) -> str | None:
    """Find the bare name beneath a chain of argument-free case and whitespace method calls.

    Args:
        value: Assigned expression to unwind; each outer lower, casefold, strip, lstrip, rstrip or upper call that takes no arguments is peeled off.

    Returns:
        The root name, which is the value's own name when it is already a bare name. None when the chain ends in anything else, such as another call,
        an attribute or a literal, or when a chain method is called with arguments (e.g. strip with a character set).
    """
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
    """Return ``(vocabulary, text, node)`` for an any()-scan or loop-scan site.

    Args:
        node: Node from the function-scope walk; only calls and plain for loops are examined, async for loops are not.

    Returns:
        The scanned iterable's name, the text name and the node to report (the any() call itself, or the if statement inside the loop). None when the
        node is neither a call nor a plain for loop, or does not match a scan shape.
    """
    if isinstance(node, ast.Call):
        return _any_scan_site(node)
    if isinstance(node, ast.For):
        return _loop_scan_site(node)
    return None


def _any_scan_site(call: ast.Call) -> tuple[str, str, ast.AST] | None:
    """Match an any() call whose generator tests each term of a named collection for containment in a name.

    The call must target the bare name any with a single generator-expression argument that has one for clause binding a bare name over a bare-name
    iterable; list comprehensions and multi-clause generators do not match.

    Args:
        call: Call node to test.

    Returns:
        The iterable's name, the text name and the call node to report. None when the call does not have the any() scan shape or its element is not a
        containment test of the term in a bare name.
    """
    if not (isinstance(call.func, ast.Name) and call.func.id == "any"):
        return None
    if len(call.args) != 1 or not isinstance(call.args[0], ast.GeneratorExp):
        return None
    generator = call.args[0]
    if len(generator.generators) != 1:
        return None
    comprehension = generator.generators[0]
    if not (isinstance(comprehension.target, ast.Name) and isinstance(comprehension.iter, ast.Name)):
        return None
    text_name = _containment_text(generator.elt, comprehension.target.id)
    if text_name is None:
        return None
    return comprehension.iter.id, text_name, call


def _loop_scan_site(loop: ast.For) -> tuple[str, str, ast.AST] | None:
    """Match a for loop over a named collection whose body tests the loop term for containment in a name.

    Only if statements placed directly in the loop body are checked, and their test must itself be the containment comparison; nested ifs, elif
    branches and boolean combinations are not examined.

    Args:
        loop: For loop to test; its target and iterable must both be bare names.

    Returns:
        The iterable's name, the text name and the first if statement in the loop body whose test matches, which is the node reported. None when the
        loop shape does not match or no such if statement exists.
    """
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
    """Return the containment target name for ``<term> in <text>`` comparisons.

    Args:
        expression: Test expression to inspect: the generator element of an any() scan or the test of an if statement in a loop scan.
        term_name: Loop or comprehension variable that must be the left operand of the comparison.

    Returns:
        The bare name on the right of the in comparison. None when the expression is not a single comparison, for any other operator including not in,
        for a chained comparison, a different left operand, or a right operand that is not a bare name (such as text.lower()).
    """
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
    """Decide whether a name contains a free-text token such as message, text or query as an underscore segment.

    Args:
        name: Text name or source-parameter name to test.

    Returns:
        True when any lowercased underscore-separated segment exactly equals an entry in _FREE_TEXT_TOKENS. Names are split only on underscores, so a
        camelCase name such as userMessage matches only if its whole lowercased form is a token.
    """
    return any(token in _FREE_TEXT_TOKENS for token in name.lower().split("_"))


def _is_collection_annotated(annotation: ast.expr | None) -> bool:
    """Whether *annotation*'s head type is a known non-str collection.

    Args:
        annotation: Parameter annotation expression, or None for an unannotated parameter.

    Returns:
        True when any head name of the annotation, including any member of a union or Optional, is in _COLLECTION_ANNOTATIONS, so str | list[str]
        counts as a collection. False for an unannotated parameter, a string forward reference, or a non-collection head such as str.
    """
    return bool(_annotation_head_names(annotation) & _COLLECTION_ANNOTATIONS)


def _annotation_head_names(annotation: ast.expr | None) -> set[str]:
    """Constructor name(s) at the head of a type annotation (``dict[..]`` -> ``dict``).

    ``Optional[...]`` / ``Union[...]`` wrappers unwrap to the head(s) they wrap,
    so ``Optional[list[str]]`` and ``Union[str, dict]`` resolve to the inner
    collection rather than the wrapper name.

    Args:
        annotation: Annotation expression to inspect, or None when the parameter has none.

    Returns:
        Set of head names: the name itself for a bare name, the final attribute of a dotted reference (typing.List gives List), the head of a
        subscripted type, the inner heads of an Optional or Union subscript, and the heads of both sides of an X | Y union. Every member is kept, so
        Union[str, dict] gives both str and dict. Empty for None, a string forward reference and other unsupported forms.
    """
    if isinstance(annotation, ast.Name):
        return {annotation.id}
    if isinstance(annotation, ast.Attribute):
        return {annotation.attr}
    if isinstance(annotation, ast.Tuple):
        return set().union(*(_annotation_head_names(element) for element in annotation.elts))
    if isinstance(annotation, ast.Subscript):
        head = _annotation_head_names(annotation.value)
        if head <= {"Optional", "Union"}:
            return _annotation_head_names(annotation.slice)
        return head
    if isinstance(annotation, ast.BinOp) and isinstance(annotation.op, ast.BitOr):
        return _annotation_head_names(annotation.left) | _annotation_head_names(annotation.right)
    return set()


def _build_finding(
    definition: RuleDefinition,
    unit: AnalysisUnit,
    node: ast.AST,
    vocabulary_name: str,
    text_name: str,
) -> Finding:
    """Build the finding for one substring vocabulary scan site, naming the vocabulary and the scanned text.

    The message names both identifiers, the remediation is the shared word-matching advice, and the metadata records them under the vocabulary and
    text keys. The line falls back to 1 and the end line to None when the node carries no position.

    Args:
        definition: Rule definition supplying the rule id, default severity, pillar, tier, confidence and secondary pillars.
        unit: Analysis unit whose file display path becomes the finding's path.
        node: Reported node, the any() call or the loop's if statement, whose line span locates the finding.
        vocabulary_name: Name of the module-level vocabulary being scanned.
        text_name: Name of the parameter or derived local the vocabulary is scanned over.

    Returns:
        The finding for the scan site.
    """
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
