"""Model the bounded values and call bindings behind Markdown-link findings.

The provenance index uses these immutable proof results and conservative merge
helpers while following a user's source. Keeping the model separate lets both
files stay readable without weakening their UI-focused explanation contracts.
"""

import ast
from dataclasses import dataclass, field
from typing import Literal

MarkdownSlot = Literal["label", "url"]
_MARKDOWN_SLOTS: tuple[MarkdownSlot, ...] = ("label", "url")
ExpressionKind = Literal["name", "attribute", "subscript", "call", "conditional", "other"]
SanitizerResolution = Literal[
    "raw",
    "unconfigured-call",
    "wrong-slot",
    "shadowed-target",
    "unsafe-arguments",
    "uncertain-provenance",
]
_DEFAULT_QUOTE_TARGETS = frozenset({"urllib.parse.quote", "urllib.parse.quote_plus"})
_MARKDOWN_DELIMITERS = frozenset("]()")


@dataclass(frozen=True, slots=True)
class ExpressionSafety:
    """Explain whether one rendered value is proved safe for one link slot.

    Safe results suppress a finding; unsafe results provide the stable reason a
    CLI or JSON user sees. Alias depth prevents safety from drifting indefinitely.

    Attributes:
        is_safe: Whether the link slot may be rendered without a finding.
        sanitizer_resolution: Stable explanation when the proof is unsafe.
        alias_hops: Number of bounded name copies; zero means a direct proof.
    """

    is_safe: bool
    sanitizer_resolution: SanitizerResolution
    alias_hops: int = 0


@dataclass(frozen=True, slots=True)
class _TrackedValue:
    """Remember a user's local value as safe or conservatively uncertain.

    The scanner stores this per slot after assignments. Missing names are raw,
    while ``uncertain`` records an overwrite or control-flow disagreement.
    """

    is_safe: bool
    alias_hops: int = 0


@dataclass(frozen=True, slots=True)
class _ResolvedCallTarget:
    """Describe a call spelling after same-file import and shadow checks.

    The provenance index uses the canonical target for configured matching and
    the boolean to explain when a user's assignment invalidated that target.
    """

    canonical_target: str | None
    is_shadowed: bool


@dataclass(slots=True)
class _CallableBindings:
    """Resolve lexical sanitizer spellings without importing user code.

    Exact imports map local aliases to canonical targets. Assignments and
    parameters shadow roots so a stale configured spelling cannot hide a finding.
    """

    imported_roots: dict[str, str] = field(default_factory=dict)
    shadowed_roots: set[str] = field(default_factory=set)

    def clone(self) -> "_CallableBindings":
        """Copy bindings so separate user branches can be merged conservatively.

        Returns:
            Independent binding state; empty mappings mean no imports are known.
        """
        return _CallableBindings(dict(self.imported_roots), set(self.shadowed_roots))

    def bind_import(self, lexical_root: str, canonical_root: str) -> None:
        """Record one exact import users may call until they rebind its root.

        Args:
            lexical_root: Name visible in the scanned file; empty means no binding.
            canonical_root: Imported dotted target; empty means it cannot be trusted.
        """
        self.imported_roots[lexical_root] = canonical_root
        self.shadowed_roots.discard(lexical_root)

    def shadow(self, lexical_root: str) -> None:
        """Invalidate a callable root after a user assignment or parameter binding.

        Args:
            lexical_root: First call-target segment; empty means no name was bound.
        """
        self.imported_roots.pop(lexical_root, None)
        self.shadowed_roots.add(lexical_root)

    def resolved_target(self, lexical_target: str) -> _ResolvedCallTarget:
        """Return the canonical target plus any user-created shadow state.

        Args:
            lexical_target: Exact dotted spelling in the user's call; empty is unresolved.

        Returns:
            Resolution whose ``None`` target means a user binding killed trust.
        """
        target_parts = lexical_target.split(".")
        lexical_root = target_parts[0]
        # A parameter or assignment can replace even an exactly configured spelling.
        if lexical_root in self.shadowed_roots:
            return _ResolvedCallTarget(None, True)
        canonical_root = self.imported_roots.get(lexical_root)
        # No import mapping means the user's exact configured spelling remains authoritative.
        if canonical_root is None:
            return _ResolvedCallTarget(lexical_target, False)
        canonical_suffix = ".".join(target_parts[1:])
        # A bare from-import alias already maps to the complete canonical call target.
        if not canonical_suffix:
            return _ResolvedCallTarget(canonical_root, False)
        return _ResolvedCallTarget(f"{canonical_root}.{canonical_suffix}", False)


@dataclass(slots=True)
class _FlowState:
    """Hold safe label/URL names and callable bindings at one source position.

    Each branch receives a copy and merges only proofs shared by every path.
    Empty value maps mean the user's local names are still raw and unproved.
    """

    label_values: dict[str, _TrackedValue] = field(default_factory=dict)
    url_values: dict[str, _TrackedValue] = field(default_factory=dict)
    callables: _CallableBindings = field(default_factory=_CallableBindings)

    def clone(self) -> "_FlowState":
        """Copy the current proof state before the user's control flow diverges.

        Returns:
            Independent state; empty value maps still mean all names are raw.
        """
        return _FlowState(
            label_values=dict(self.label_values),
            url_values=dict(self.url_values),
            callables=self.callables.clone(),
        )

    def values_for(self, slot: MarkdownSlot) -> dict[str, _TrackedValue]:
        """Return the name map used to explain the requested user-visible slot.

        Args:
            slot: ``label`` for display text or ``url`` for the click target.

        Returns:
            Mutable map for that slot; empty means no local value is proved safe.
        """
        # Label and URL sanitizers are deliberately not interchangeable.
        if slot == "label":
            return self.label_values
        return self.url_values


def expression_kind(expression: ast.expr) -> ExpressionKind:
    """Return the bounded syntax label serialized for an emitted finding.

    Args:
        expression: Raw or unresolved slot value from the user's link.

    Returns:
        Stable enum; uncommon syntax collapses to ``other`` rather than leaking AST names.
    """
    # A bare local/global identifier is the most common raw user-input shape.
    if isinstance(expression, ast.Name):
        return "name"
    # Attribute reads often represent model or request fields shown in the UI.
    if isinstance(expression, ast.Attribute):
        return "attribute"
    # Subscripts represent mapping/list data selected before rendering.
    if isinstance(expression, ast.Subscript):
        return "subscript"
    # Calls explain that the wrapper existed but was not a proved sanitizer.
    if isinstance(expression, ast.Call):
        return "call"
    # A conditional tells users at least one runtime branch remained unsafe.
    if isinstance(expression, ast.IfExp):
        return "conditional"
    return "other"


def _safe(*, alias_hops: int = 0) -> ExpressionSafety:
    """Create an internal safe proof; its reason is never serialized to users.

    Args:
        alias_hops: Number of name-to-name copies; zero means direct proof.

    Returns:
        Safe expression result with bounded alias depth.
    """
    return ExpressionSafety(True, "raw", alias_hops)


def _unsafe(resolution: SanitizerResolution) -> ExpressionSafety:
    """Create an unsafe result carrying the user's remediation reason.

    Args:
        resolution: Stable reason emitted in `sanitizerResolution` metadata.

    Returns:
        Unsafe expression result with no transferable alias proof.
    """
    return ExpressionSafety(False, resolution)


def combine_expression_safety(proofs: list[ExpressionSafety]) -> ExpressionSafety:
    """Trust a composite value only when every possible rendered part is safe.

    Args:
        proofs: Child proofs; an empty list means the expression has no dynamic values.

    Returns:
        Safe combined proof, otherwise an uncertain-provenance finding reason.
    """
    # No dynamic child means the user's expression is effectively literal.
    if not proofs:
        return _safe()
    # Any unsafe branch can supply the final rendered value at runtime.
    if not all(proof.is_safe for proof in proofs):
        return _unsafe("uncertain-provenance")
    return _safe(alias_hops=max(proof.alias_hops for proof in proofs))


def combine_composed_safety(proofs: list[ExpressionSafety]) -> ExpressionSafety:
    """Classify concatenated parts as raw unless an earlier flow proof was uncertain.

    Args:
        proofs: Contributing expression proofs; empty means no runtime user value.

    Returns:
        Safe only when every part is safe; otherwise raw or uncertain provenance.
    """
    # A composition without dynamic parts is effectively a literal.
    if not proofs:
        return _safe()
    # Every contributing part must be safe before the combined rendering is safe.
    if all(proof.is_safe for proof in proofs):
        return _safe(alias_hops=max(proof.alias_hops for proof in proofs))
    # An overwritten or branch-merged child preserves its more specific uncertainty.
    if any(proof.sanitizer_resolution == "uncertain-provenance" for proof in proofs):
        return _unsafe("uncertain-provenance")
    return _unsafe("raw")


def is_quote_call_delimiter_safe(call: ast.Call) -> bool:
    """Return whether a default quote call cannot preserve `]`, `(`, or `)`.

    Args:
        call: Exact/canonical urllib quote call selected by the user.

    Returns:
        ``True`` for no `safe` argument or a delimiter-free literal; splats are false.
    """
    # Positional splats can supply an unknown second `safe` argument.
    if any(isinstance(argument, ast.Starred) for argument in call.args):
        return False
    # Keyword splats can replace `safe` without showing its literal value.
    if any(keyword_argument.arg is None for keyword_argument in call.keywords):
        return False
    positional_safe = call.args[1] if len(call.args) > 1 else None
    keyword_safe_values = [
        keyword_argument.value
        for keyword_argument in call.keywords
        if keyword_argument.arg == "safe"
    ]
    # Duplicate or positional-plus-keyword safe values are invalid and cannot prove safety.
    if len(keyword_safe_values) > 1 or (positional_safe is not None and keyword_safe_values):
        return False
    keyword_safe = keyword_safe_values[0] if keyword_safe_values else None
    selected_safe = positional_safe if positional_safe is not None else keyword_safe
    # Omitting `safe` uses urllib's delimiter-removing default.
    if selected_safe is None:
        return True
    # Dynamic/non-string safe values may retain the exact Markdown attack delimiters.
    if not isinstance(selected_safe, ast.Constant) or not isinstance(selected_safe.value, str):
        return False
    return not (_MARKDOWN_DELIMITERS & set(selected_safe.value))


def function_parameter_names(arguments: ast.arguments) -> set[str]:
    """Return every parameter that can shadow a configured callable in a function.

    Args:
        arguments: Parsed function signature; empty arguments mean no shadowing.

    Returns:
        Parameter names across positional, keyword-only, variadic, and keyword variadic forms.
    """
    parameters = [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]
    parameter_names = {parameter.arg for parameter in parameters}
    # A missing `*args` parameter introduces no local callable root.
    if arguments.vararg is not None:
        parameter_names.add(arguments.vararg.arg)
    # A missing `**kwargs` parameter likewise introduces no local root.
    if arguments.kwarg is not None:
        parameter_names.add(arguments.kwarg.arg)
    return parameter_names


def bound_names(target: ast.expr) -> set[str]:
    """Return local identifiers directly bound by one assignment-like target.

    Args:
        target: Name, unpacking, starred, attribute, or subscript target.

    Returns:
        Bound local names; empty means only an object attribute/item changed.
    """
    # A direct name replaces its prior value and callable identity.
    if isinstance(target, ast.Name):
        return {target.id}
    # Unpacking binds every nested local independently.
    if isinstance(target, (ast.Tuple, ast.List)):
        names: set[str] = set()
        # Each element may contain another user-visible unpacking shape.
        for unpacked_target in target.elts:
            names.update(bound_names(unpacked_target))
        return names
    # A starred target delegates its binding to the inner name/unpacking shape.
    if isinstance(target, ast.Starred):
        return bound_names(target.value)
    return set()


def target_root_name(target: ast.expr) -> str | None:
    """Return the root changed by an attribute/subscript assignment, if any.

    Args:
        target: User assignment target; a literal/unpacking has no single root.

    Returns:
        Root identifier, or ``None`` when no callable namespace can be invalidated.
    """
    current: ast.expr = target
    # Attribute/item writes walk back to the namespace users could later call through.
    while isinstance(current, (ast.Attribute, ast.Subscript)):
        current = current.value
    # A name root such as `urllib` can shadow a configured dotted target.
    if isinstance(current, ast.Name):
        return current.id
    return None


def merge_flow_states(states: list[_FlowState]) -> _FlowState:
    """Keep only value/import proofs shared by every possible user execution path.

    Args:
        states: Branch states; empty means no path established a proof.

    Returns:
        Conservative join where any disagreement becomes uncertain or shadowed.
    """
    # No reachable path provides a proof for later source positions.
    if not states:
        return _FlowState()
    return _FlowState(
        label_values=_merge_value_maps([state.label_values for state in states]),
        url_values=_merge_value_maps([state.url_values for state in states]),
        callables=_merge_callable_bindings([state.callables for state in states]),
    )


def _merge_value_maps(value_maps: list[dict[str, _TrackedValue]]) -> dict[str, _TrackedValue]:
    """Merge slot values so only all-safe branches remain safe for users.

    Args:
        value_maps: Same-slot state from every branch; empty maps mean raw values.

    Returns:
        Joined values; absent on every path stays absent, disagreement becomes uncertain.
    """
    all_names: set[str] = set()
    # Every name appearing in any branch must be evaluated across all paths.
    for value_map in value_maps:
        all_names.update(value_map)
    merged_values: dict[str, _TrackedValue] = {}
    # A name is safe only when every branch carries a safe proof for it.
    for value_name in all_names:
        branch_values = [value_map.get(value_name) for value_map in value_maps]
        # Missing on every path means the name remains an ordinary raw value.
        if all(branch_value is None for branch_value in branch_values):
            continue
        # Every path must carry a safe proof before the merged display is trusted.
        if all(branch_value is not None and branch_value.is_safe for branch_value in branch_values):
            safe_values = [
                branch_value for branch_value in branch_values if branch_value is not None
            ]
            merged_values[value_name] = _TrackedValue(
                is_safe=True,
                alias_hops=max(value.alias_hops for value in safe_values),
            )
        else:
            merged_values[value_name] = _TrackedValue(is_safe=False)
    return merged_values


def _merge_callable_bindings(bindings: list[_CallableBindings]) -> _CallableBindings:
    """Merge import aliases so any shadowed or divergent path loses callable trust.

    Args:
        bindings: Callable state from each branch; empty means no imports are proved.

    Returns:
        Shared exact bindings plus roots shadowed on any or divergent paths.
    """
    merged = _CallableBindings()
    all_roots: set[str] = set()
    # Imported and shadowed roots both participate in the user's branch join.
    for branch_bindings in bindings:
        all_roots.update(branch_bindings.imported_roots)
        all_roots.update(branch_bindings.shadowed_roots)
    # Each root survives only when every path maps it to the same canonical target.
    for lexical_root in all_roots:
        # Any explicit shadow path is enough to distrust the root after the join.
        if any(lexical_root in branch.shadowed_roots for branch in bindings):
            merged.shadow(lexical_root)
            continue
        canonical_targets = {branch.imported_roots.get(lexical_root) for branch in bindings}
        # Equal non-empty canonical targets preserve the import proof.
        if len(canonical_targets) == 1 and None not in canonical_targets:
            canonical_target = next(iter(canonical_targets))
            # The guard above excludes `None`, but keep the runtime branch explicit for users.
            if canonical_target is not None:
                merged.bind_import(lexical_root, canonical_target)
        else:
            merged.shadow(lexical_root)
    return merged
