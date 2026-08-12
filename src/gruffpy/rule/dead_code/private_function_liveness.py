"""Index scanned imports that prove a module-private function is still live.

The project rule uses this module after discovery has produced every parsed
Python file. It distinguishes an import declaration from the later load a user
creates through a registry, callback table, decorator, or ordinary expression.
Ambiguous module layouts never suppress deletion advice silently.
"""

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Literal, TypeAlias, TypeGuard

from gruffpy.parser.analysis_unit import AnalysisUnit

PrivateFunctionKey: TypeAlias = tuple[str, str]
ExternalReferenceCoverage: TypeAlias = Literal["complete", "ambiguous"]
_CONDITIONAL_STATEMENTS: tuple[type[ast.AST], ...] = (
    ast.If,
    ast.For,
    ast.AsyncFor,
    ast.While,
    ast.Try,
    ast.TryStar,
    ast.Match,
    ast.match_case,
    ast.ExceptHandler,
)
_ScopeNode: TypeAlias = (
    ast.Module
    | ast.FunctionDef
    | ast.AsyncFunctionDef
    | ast.Lambda
    | ast.ClassDef
    | ast.ListComp
    | ast.SetComp
    | ast.DictComp
    | ast.GeneratorExp
)


@dataclass(frozen=True, slots=True)
class PrivateFunctionLiveness:
    """Record project evidence used before showing deletion advice.

    A live key has one uniquely resolved later load. An ambiguous key had a
    real load, but more than one scanned module could own it, so the finding
    remains visible with lower confidence.
    """

    live_keys: frozenset[PrivateFunctionKey]
    ambiguous_keys: frozenset[PrivateFunctionKey]

    def is_live(self, file_path: str, function_name: str) -> bool:
        """Return whether a scanned consumer proved this function is used.

        Args:
            file_path: Project-relative producer path shown in the finding.
            function_name: Private top-level function imported by a consumer.

        Returns:
            True only for one unambiguous import followed by an actual load.
        """
        return (file_path, function_name) in self.live_keys

    def coverage_for(
        self,
        file_path: str,
        function_name: str,
    ) -> ExternalReferenceCoverage:
        """Describe whether scanned external-reference evidence was conclusive.

        Args:
            file_path: Project-relative producer path shown in the finding.
            function_name: Private top-level function that remains unreferenced.

        Returns:
            ``ambiguous`` after a duplicate-module load; otherwise ``complete``.
        """
        # A duplicate resolved path means the user load cannot identify one producer.
        if (file_path, function_name) in self.ambiguous_keys:
            return "ambiguous"
        return "complete"


@dataclass(frozen=True, slots=True)
class _ImportBinding:
    """Describe one imported name visible inside a lexical source scope.

    Function bindings carry the producer's private name. Module bindings keep
    that field empty and wait for a later attribute such as ``helpers._run``.
    """

    bound_name: str
    module_paths: tuple[str, ...]
    imported_function_name: str | None
    attribute_prefix: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _BindingEvent:
    """Represent an import or rebind at one deterministic source position.

    ``binding`` is None after the user overwrites or deletes the imported name;
    otherwise it identifies the candidate producer modules for later loads.
    ``is_conditional`` marks a rebind the user's control flow may skip, which
    therefore cannot prove an earlier import is unreachable at a later load.
    """

    position: tuple[int, int, int]
    binding: _ImportBinding | None
    is_conditional: bool = False


@dataclass(frozen=True, slots=True)
class _ScopeIndex:
    """Map every AST node to the lexical lookup scope a user expression sees.

    Parent scopes model Python closures while skipping class namespaces for
    method bodies, so a method resolves module imports without treating class
    attributes as captured locals.
    """

    scope_by_node: dict[int, int]
    parent_by_scope: dict[int, int | None]
    scope_nodes: dict[int, _ScopeNode]


@dataclass(frozen=True, slots=True)
class _LoadEvidenceIndex:
    """Bundle the binding history needed to classify later user loads.

    Each consumer file builds this once after import and rebind indexing. Load
    handlers then share the same scope, candidate, and result collections.
    """

    scope_index: _ScopeIndex
    events_by_scope_and_name: dict[tuple[int, str], list[_BindingEvent]]
    bound_names: set[tuple[int, str]]
    candidate_keys: frozenset[PrivateFunctionKey]
    live_keys: set[PrivateFunctionKey]
    ambiguous_keys: set[PrivateFunctionKey]


class _ModuleResolver:
    """Resolve import text only against modules present in the scanned project.

    Absolute imports use unique path suffixes, supporting flat and src layouts
    without one configured source root. Relative imports use the importing
    file's exact directory. Multiple matches remain deliberately ambiguous.
    """

    def __init__(self, units: list[AnalysisUnit]) -> None:
        """Index project-relative Python paths for deterministic import lookup.

        Args:
            units: Parsed files selected for this user scan; empty is valid.
        """
        normalized_paths: set[str] = set()
        # Only parsed Python modules can own a statically resolved function import.
        for unit in units:
            # A parser failure has no reliable module declarations for the user.
            if not isinstance(unit.tree, ast.Module):
                continue
            normalized_paths.add(_normalized_path(unit.file.display_path))
        self._paths = frozenset(normalized_paths)

        paths_by_module_suffix: defaultdict[str, set[str]] = defaultdict(set)
        # Each suffix lets the same project work as ``pkg`` or ``src.pkg``.
        for file_path in self._paths:
            # A path contributes only syntactically importable dotted suffixes.
            for module_suffix in _module_suffixes(file_path):
                paths_by_module_suffix[module_suffix].add(file_path)
        # Sorted tuples make duplicate-module outcomes stable across discovery order.
        self._absolute_paths = {
            module_name: tuple(sorted(paths))
            for module_name, paths in paths_by_module_suffix.items()
        }

    def resolve(
        self,
        importing_file_path: str,
        module_name: str,
        relative_level: int,
    ) -> tuple[str, ...]:
        """Resolve one AST import module to zero, one, or many scanned files.

        Args:
            importing_file_path: Consumer path used for relative import lookup.
            module_name: Dotted AST module text; empty means the current package.
            relative_level: Zero for absolute imports, otherwise the dot count.

        Returns:
            Sorted matching producer paths; empty means no scanned target.
        """
        # Relative imports belong to the consumer's package path, not a global suffix.
        if relative_level > 0:
            return self._resolve_relative(
                importing_file_path,
                module_name,
                relative_level,
            )
        return self._absolute_paths.get(module_name, ())

    def resolve_child(
        self,
        importing_file_path: str,
        module_name: str,
        relative_level: int,
        child_name: str,
    ) -> tuple[str, ...]:
        """Resolve ``from package import child`` when child is a scanned module.

        Args:
            importing_file_path: Consumer path used for relative import lookup.
            module_name: Parent package named by the import statement.
            relative_level: Zero for absolute imports, otherwise the dot count.
            child_name: Imported attribute that may instead be a child module.

        Returns:
            Sorted child-module paths; empty means treat child as a symbol.
        """
        # Empty parent text means ``from . import child`` and contributes no dot.
        child_module_name = ".".join(part for part in (module_name, child_name) if part)
        return self.resolve(importing_file_path, child_module_name, relative_level)

    def _resolve_relative(
        self,
        importing_file_path: str,
        module_name: str,
        relative_level: int,
    ) -> tuple[str, ...]:
        """Resolve a dotted relative import from the consumer's exact directory.

        Args:
            importing_file_path: Consumer path whose package anchors the dots.
            module_name: Dotted path following the relative dots; empty is valid.
            relative_level: Positive number of leading dots from the AST.

        Returns:
            Exact file/package matches from the scanned set; empty when outside it.
        """
        importing_parent_parts = list(
            PurePosixPath(_normalized_path(importing_file_path)).parent.parts
        )
        parent_levels_to_remove = relative_level - 1
        # Too many dots leave the scanned package, so no user file can be proven.
        if parent_levels_to_remove > len(importing_parent_parts):
            return ()
        retained_parent_parts = importing_parent_parts[
            : len(importing_parent_parts) - parent_levels_to_remove
        ]
        # An empty module name targets the current package initializer directly.
        module_parts = [part for part in module_name.split(".") if part]
        target_path = PurePosixPath(*retained_parent_parts, *module_parts)
        candidate_paths = (
            str(target_path.with_suffix(".py")),
            str(target_path / "__init__.py"),
        )
        # Exact relative matches cannot drift between unrelated source roots.
        return tuple(path for path in candidate_paths if path in self._paths)


def build_private_function_liveness(
    units: list[AnalysisUnit],
    candidate_keys: frozenset[PrivateFunctionKey],
) -> PrivateFunctionLiveness:
    """Build one project-wide index of actual imported private-function loads.

    Args:
        units: Parsed files selected for the user's current scan; empty is valid.
        candidate_keys: Top-level private functions eligible for deletion advice.

    Returns:
        Live and ambiguous candidate keys; both collections may be empty.
    """
    resolver = _ModuleResolver(units)
    live_keys: set[PrivateFunctionKey] = set()
    ambiguous_keys: set[PrivateFunctionKey] = set()
    # Every parsed user module is traversed once to build the external index.
    for unit in units:
        # Text files and parse failures cannot contribute reliable import loads.
        if not isinstance(unit.tree, ast.Module):
            continue
        _collect_unit_liveness(
            unit,
            resolver,
            candidate_keys,
            live_keys,
            ambiguous_keys,
        )
    return PrivateFunctionLiveness(
        live_keys=frozenset(live_keys),
        ambiguous_keys=frozenset(ambiguous_keys),
    )


def _collect_unit_liveness(
    unit: AnalysisUnit,
    resolver: _ModuleResolver,
    candidate_keys: frozenset[PrivateFunctionKey],
    live_keys: set[PrivateFunctionKey],
    ambiguous_keys: set[PrivateFunctionKey],
) -> None:
    """Add one consumer module's proven and ambiguous loads to the project index.

    Args:
        unit: Parsed consumer module; its tree is guaranteed to be an AST module.
        resolver: Scanned-file resolver for absolute and relative imports.
        candidate_keys: Producer functions that could receive deletion advice.
        live_keys: Mutable set receiving uniquely resolved loaded functions.
        ambiguous_keys: Mutable set receiving loaded but duplicate module targets.

    Returns:
        None; the two supplied evidence sets are updated in place.
    """
    tree = unit.tree
    # The caller admits only parsed modules, keeping this None/type guard fail closed.
    if not isinstance(tree, ast.Module):
        return
    nodes = list(ast.walk(tree))
    scope_index = _build_scope_index(nodes, tree)
    events_by_scope_and_name, bound_names = _build_binding_events(
        unit,
        nodes,
        scope_index,
        resolver,
        candidate_keys,
    )
    load_evidence = _LoadEvidenceIndex(
        scope_index=scope_index,
        events_by_scope_and_name=events_by_scope_and_name,
        bound_names=bound_names,
        candidate_keys=candidate_keys,
        live_keys=live_keys,
        ambiguous_keys=ambiguous_keys,
    )
    _record_actual_import_loads(nodes, load_evidence)


def _build_binding_events(
    unit: AnalysisUnit,
    nodes: list[ast.AST],
    scope_index: _ScopeIndex,
    resolver: _ModuleResolver,
    candidate_keys: frozenset[PrivateFunctionKey],
) -> tuple[dict[tuple[int, str], list[_BindingEvent]], set[tuple[int, str]]]:
    """Index imports and rebinds before interpreting later user expressions.

    Args:
        unit: Parsed consumer file whose path anchors relative imports.
        nodes: One materialized AST walk; empty means no bindings or loads.
        scope_index: Lexical ownership used to separate local user bindings.
        resolver: Scanned-module resolver used for each import declaration.
        candidate_keys: Producer functions that may be package attributes.

    Returns:
        Sorted event histories and locally bound names; both may be empty.
    """
    events_by_scope_and_name: defaultdict[tuple[int, str], list[_BindingEvent]] = defaultdict(list)
    bound_names: set[tuple[int, str]] = set()
    externally_declared_names = _externally_declared_names(nodes, scope_index)
    # The first in-memory pass records imports and every lexical invalidation.
    for sequence, node in enumerate(nodes):
        event_scope = _event_scope_id(node, scope_index)
        position = _source_position(node, sequence)
        # Import statements create resolvable bindings but are not themselves use.
        if isinstance(node, ast.Import):
            # Each alias can bind a different module name in the user's scope.
            for binding in _bindings_for_import(node, resolver):
                events_by_scope_and_name[(event_scope, binding.bound_name)].append(
                    _BindingEvent(position=position, binding=binding)
                )
                bound_names.add((event_scope, binding.bound_name))
        # From-import aliases may bind a function directly or a scanned child module.
        elif isinstance(node, ast.ImportFrom):
            # Each alias needs its own later-load and rebinding history.
            for binding in _bindings_for_from_import(unit, node, resolver, candidate_keys):
                events_by_scope_and_name[(event_scope, binding.bound_name)].append(
                    _BindingEvent(position=position, binding=binding)
                )
                bound_names.add((event_scope, binding.bound_name))

        # Assignments, parameters, definitions, and pattern captures invalidate imports.
        is_conditional = _is_conditionally_executed(node)
        for rebound_name in _rebound_names(node):
            # ``global``/``nonlocal`` send the store to an outer scope, so the name
            # never becomes a local shadow of the import this scope can still see.
            if rebound_name in externally_declared_names.get(event_scope, frozenset()):
                continue
            events_by_scope_and_name[(event_scope, rebound_name)].append(
                _BindingEvent(position=position, binding=None, is_conditional=is_conditional)
            )
            bound_names.add((event_scope, rebound_name))

    # Sorted histories make the active binding independent of AST traversal order.
    for binding_events in events_by_scope_and_name.values():
        binding_events.sort(key=lambda event: event.position)
    return events_by_scope_and_name, bound_names


def _record_actual_import_loads(
    nodes: list[ast.AST],
    load_evidence: _LoadEvidenceIndex,
) -> None:
    """Record real Name and Attribute loads after import declarations.

    Args:
        nodes: One materialized AST walk; empty means the user loaded nothing.
        load_evidence: Shared binding history, candidates, and result collections.

    Returns:
        None; live or ambiguous candidate sets are updated in place.
    """
    # The second in-memory pass consumes only real Name/Attribute loads after imports.
    for sequence, node in enumerate(nodes):
        load_position = _source_position(node, sequence)
        # A complete attribute chain is handled once at its outermost node.
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            _record_attribute_load(node, load_position, load_evidence)
        # A direct Name load proves a from-imported private function is used.
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            _record_direct_name_load(node, load_position, load_evidence)


def _record_attribute_load(
    node: ast.Attribute,
    load_position: tuple[int, int, int],
    load_evidence: _LoadEvidenceIndex,
) -> None:
    """Classify one loaded module attribute as live, ambiguous, or irrelevant.

    Args:
        node: Outermost attribute expression the user's code actually loads.
        load_position: Source order used to select the active import binding.
        load_evidence: Shared binding history, candidates, and result collections.

    Returns:
        None; a resolved private-function key may be added to the result sets.
    """
    parent = getattr(node, "parent", None)
    # The outer attribute owns the full path; processing an inner part duplicates use.
    if isinstance(parent, ast.Attribute) and parent.value is node:
        return
    root_name, attribute_parts = _attribute_chain(node)
    # Dynamic or non-private attributes cannot prove one candidate's liveness.
    if root_name is None or not attribute_parts or not attribute_parts[-1].startswith("_"):
        return
    attribute_binding = _active_binding(
        root_name.id,
        root_name,
        load_position,
        load_evidence.scope_index,
        load_evidence.events_by_scope_and_name,
        load_evidence.bound_names,
    )
    # Only module imports resolve a later private attribute to a producer.
    if attribute_binding is None or attribute_binding.imported_function_name is not None:
        return
    # Plain imports may require a prefix such as package.module before the symbol.
    if attribute_parts[:-1] != attribute_binding.attribute_prefix:
        return
    _record_loaded_candidate(
        attribute_binding,
        attribute_parts[-1],
        load_evidence.candidate_keys,
        load_evidence.live_keys,
        load_evidence.ambiguous_keys,
    )


def _record_direct_name_load(
    node: ast.Name,
    load_position: tuple[int, int, int],
    load_evidence: _LoadEvidenceIndex,
) -> None:
    """Classify one direct load of a from-imported private function.

    Args:
        node: Loaded user identifier that may refer to a direct function import.
        load_position: Source order used to select the active import binding.
        load_evidence: Shared binding history, candidates, and result collections.

    Returns:
        None; a resolved private-function key may be added to the result sets.
    """
    parent = getattr(node, "parent", None)
    # Attribute roots are evaluated by the complete-chain handler instead.
    if isinstance(parent, ast.Attribute):
        return
    direct_binding = _active_binding(
        node.id,
        node,
        load_position,
        load_evidence.scope_index,
        load_evidence.events_by_scope_and_name,
        load_evidence.bound_names,
    )
    # A module Name alone does not identify which private function was loaded.
    if direct_binding is None or direct_binding.imported_function_name is None:
        return
    _record_loaded_candidate(
        direct_binding,
        direct_binding.imported_function_name,
        load_evidence.candidate_keys,
        load_evidence.live_keys,
        load_evidence.ambiguous_keys,
    )


def _build_scope_index(nodes: list[ast.AST], tree: ast.Module) -> _ScopeIndex:
    """Assign each AST node to one lexical scope in a single parent-first pass.

    Args:
        nodes: One materialized ``ast.walk`` result; parent nodes occur first.
        tree: Root module selected by the user; never None.

    Returns:
        Node-to-scope and closure-parent mappings for binding lookup.
    """
    root_scope_id = id(tree)
    scope_by_node: dict[int, int] = {root_scope_id: root_scope_id}
    parent_by_scope: dict[int, int | None] = {root_scope_id: None}
    scope_nodes: dict[int, _ScopeNode] = {root_scope_id: tree}
    evaluation_scope_overrides: dict[int, int] = {}
    # The root is already indexed; every later node inherits or opens a scope.
    for node in nodes[1:]:
        parent = getattr(node, "parent", None)
        # Hand-built ASTs without parent links stay safely in the module scope.
        if not isinstance(parent, ast.AST):
            scope_by_node[id(node)] = root_scope_id
            continue
        parent_scope_id = evaluation_scope_overrides.get(
            id(node),
            scope_by_node.get(id(parent), root_scope_id),
        )
        # Functions, classes, lambdas, and comprehensions own their local bindings.
        if _is_scope_node(node):
            node_scope_id = id(node)
            scope_by_node[node_scope_id] = node_scope_id
            scope_nodes[node_scope_id] = node
            lexical_parent_scope_id: int | None = parent_scope_id
            # Function-like scopes close over the class's parent, not its namespace.
            if isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.Lambda,
                    ast.ListComp,
                    ast.SetComp,
                    ast.DictComp,
                    ast.GeneratorExp,
                ),
            ) and isinstance(scope_nodes.get(parent_scope_id), ast.ClassDef):
                lexical_parent_scope_id = parent_by_scope[parent_scope_id]
            parent_by_scope[node_scope_id] = lexical_parent_scope_id
            # Headers and the leftmost comprehension iterable execute outside the new scope.
            for expression in _outer_evaluated_expressions(node):
                evaluation_scope_overrides[id(expression)] = parent_scope_id
        else:
            scope_by_node[id(node)] = parent_scope_id
    return _ScopeIndex(
        scope_by_node=scope_by_node,
        parent_by_scope=parent_by_scope,
        scope_nodes=scope_nodes,
    )


def _outer_evaluated_expressions(node: _ScopeNode) -> tuple[ast.expr, ...]:
    """Return expressions Python evaluates before entering a new lexical scope.

    Args:
        node: Function, class, lambda, or comprehension that opens a scope.

    Returns:
        Expression roots that inherit the containing scope rather than ``node``.
    """
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        argument_annotations = tuple(
            argument.annotation
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if argument.annotation is not None
        )
        optional_argument_annotations = tuple(
            argument.annotation
            for argument in (node.args.vararg, node.args.kwarg)
            if argument is not None and argument.annotation is not None
        )
        return tuple(
            expression
            for expression in (
                *node.decorator_list,
                *node.args.defaults,
                *node.args.kw_defaults,
                *argument_annotations,
                *optional_argument_annotations,
                node.returns,
            )
            if expression is not None
        )
    if isinstance(node, ast.Lambda):
        return tuple(
            expression
            for expression in (*node.args.defaults, *node.args.kw_defaults)
            if expression is not None
        )
    if isinstance(node, ast.ClassDef):
        return (*node.decorator_list, *node.bases, *(keyword.value for keyword in node.keywords))
    if isinstance(node, ast.Module):
        return ()
    # Only the leftmost iterable runs before the comprehension's local target exists.
    return (node.generators[0].iter,) if node.generators else ()


def _is_scope_node(node: ast.AST) -> TypeGuard[_ScopeNode]:
    """Return whether a node owns Python bindings visible to nested expressions.

    Args:
        node: Parsed node from a user's module; never None.

    Returns:
        True for module/function/class/lambda/comprehension scopes.
    """
    return isinstance(
        node,
        (
            ast.Module,
            ast.FunctionDef,
            ast.AsyncFunctionDef,
            ast.Lambda,
            ast.ClassDef,
            ast.ListComp,
            ast.SetComp,
            ast.DictComp,
            ast.GeneratorExp,
        ),
    )


def _event_scope_id(node: ast.AST, scope_index: _ScopeIndex) -> int:
    """Return the scope where this node binds an imported or replacement name.

    Args:
        node: Import, assignment, parameter, or definition being indexed.
        scope_index: Lexical ownership map for the current user module.

    Returns:
        Stable in-memory scope identity used only during this analysis run.
    """
    # A def/class name binds in its containing scope, not inside its new body.
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        parent = getattr(node, "parent", None)
        # A malformed detached definition falls back to its own indexed scope.
        if isinstance(parent, ast.AST):
            return scope_index.scope_by_node.get(id(parent), id(node))
    return scope_index.scope_by_node.get(id(node), next(iter(scope_index.parent_by_scope)))


def _bindings_for_import(
    node: ast.Import,
    resolver: _ModuleResolver,
) -> tuple[_ImportBinding, ...]:
    """Build module bindings for one absolute ``import`` statement.

    Args:
        node: User import declaration containing one or more aliases.
        resolver: Scanned-file resolver for the imported dotted modules.

    Returns:
        Bindings for resolvable or unresolved modules; empty only for no aliases.
    """
    bindings: list[_ImportBinding] = []
    # Every comma-separated import has independent alias and attribute semantics.
    for alias in node.names:
        module_parts = tuple(alias.name.split("."))
        bound_name = alias.asname or module_parts[0]
        attribute_prefix = () if alias.asname else module_parts[1:]
        bindings.append(
            _ImportBinding(
                bound_name=bound_name,
                module_paths=resolver.resolve("", alias.name, 0),
                imported_function_name=None,
                attribute_prefix=attribute_prefix,
            )
        )
    return tuple(bindings)


def _bindings_for_from_import(
    unit: AnalysisUnit,
    node: ast.ImportFrom,
    resolver: _ModuleResolver,
    candidate_keys: frozenset[PrivateFunctionKey],
) -> tuple[_ImportBinding, ...]:
    """Build direct-function or child-module bindings for a from-import.

    Args:
        unit: Consumer file whose path anchors relative imports.
        node: User from-import declaration containing one or more aliases.
        resolver: Scanned-file resolver for parent and child modules.
        candidate_keys: Producer functions eligible for liveness evidence.

    Returns:
        Bindings for explicit aliases; star imports intentionally return none.
    """
    module_name = node.module or ""
    parent_module_paths = resolver.resolve(
        unit.file.display_path,
        module_name,
        node.level,
    )
    bindings: list[_ImportBinding] = []
    # Each from-import alias must earn liveness through its own later load.
    for alias in node.names:
        # Star imports cannot prove which private function a later name came from.
        if alias.name == "*":
            continue
        # Python uses an existing package attribute before importing a same-named child.
        if any((module_path, alias.name) in candidate_keys for module_path in parent_module_paths):
            bindings.append(
                _ImportBinding(
                    bound_name=alias.asname or alias.name,
                    module_paths=parent_module_paths,
                    imported_function_name=alias.name,
                    attribute_prefix=(),
                )
            )
            continue
        child_module_paths = resolver.resolve_child(
            unit.file.display_path,
            module_name,
            node.level,
            alias.name,
        )
        # A scanned child module is used through attributes, not as a direct function.
        if child_module_paths:
            bindings.append(
                _ImportBinding(
                    bound_name=alias.asname or alias.name,
                    module_paths=child_module_paths,
                    imported_function_name=None,
                    attribute_prefix=(),
                )
            )
            continue
        bindings.append(
            _ImportBinding(
                bound_name=alias.asname or alias.name,
                module_paths=parent_module_paths,
                imported_function_name=alias.name,
                attribute_prefix=(),
            )
        )
    return tuple(bindings)


def _externally_declared_names(
    nodes: list[ast.AST],
    scope_index: _ScopeIndex,
) -> dict[int, frozenset[str]]:
    """Map each scope to the names it resolves outside itself.

    A ``global`` or ``nonlocal`` statement means later stores in that scope
    rebind an outer name instead of creating a local shadow, so the scope keeps
    seeing whatever import the outer scope established.

    Args:
        nodes: One materialized AST walk; empty means no declarations exist.
        scope_index: Lexical ownership used to attribute each declaration.

    Returns:
        Declared names per scope; an absent scope declares nothing.
    """
    declared_names: defaultdict[int, set[str]] = defaultdict(set)
    # Each declaration applies to every store of that name in the same scope.
    for node in nodes:
        # Only these two statements move a scope's stores to an outer binding.
        if not isinstance(node, (ast.Global, ast.Nonlocal)):
            continue
        declaring_scope = scope_index.scope_by_node.get(id(node))
        # A detached declaration without an indexed scope binds nothing here.
        if declaring_scope is None:
            continue
        declared_names[declaring_scope].update(node.names)
    return {scope_id: frozenset(names) for scope_id, names in declared_names.items()}


def _is_conditionally_executed(node: ast.AST) -> bool:
    """Return whether the user's control flow can skip this binding.

    A rebind the interpreter may never reach cannot prove an earlier import is
    unreachable at a later load, so deletion advice must not rely on it. Walking
    stops at the first enclosing scope because an outer branch does not make a
    binding inside a nested scope conditional within that scope.

    Args:
        node: Binding node whose enclosing statements are inspected.

    Returns:
        True when a branch, loop, handler, or match case may skip the binding.
    """
    current = getattr(node, "parent", None)
    # Hand-built ASTs without parent links keep the previous unconditional reading.
    while isinstance(current, ast.AST):
        # A nested scope boundary ends the containing statements for this binding.
        if _is_scope_node(current):
            return False
        if isinstance(current, _CONDITIONAL_STATEMENTS):
            return True
        current = getattr(current, "parent", None)
    return False


def _rebound_names(node: ast.AST) -> tuple[str, ...]:
    """Return names this AST node binds independently of import declarations.

    Args:
        node: Parsed node from the user's module; never None.

    Returns:
        Rebound names, or an empty tuple when the node changes no binding.
    """
    match node:
        case ast.Name(id=name, ctx=ast.Store() | ast.Del()):
            return (name,)
        case ast.arg(arg=name):
            return (name,)
        case ast.FunctionDef(name=name) | ast.AsyncFunctionDef(name=name) | ast.ClassDef(name=name):
            return (name,)
        case ast.ExceptHandler(name=name) if isinstance(name, str):
            return (name,)
        case ast.MatchAs(name=name) | ast.MatchStar(name=name) if isinstance(name, str):
            return (name,)
        case ast.MatchMapping(rest=name) if isinstance(name, str):
            return (name,)
        case _:
            return ()


def _active_binding(
    name: str,
    load_node: ast.AST,
    load_position: tuple[int, int, int],
    scope_index: _ScopeIndex,
    events_by_scope_and_name: dict[tuple[int, str], list[_BindingEvent]],
    bound_names: set[tuple[int, str]],
) -> _ImportBinding | None:
    """Resolve the import binding visible at one later Name/Attribute load.

    Args:
        name: Local identifier loaded by the user's expression.
        load_node: Name or attribute root whose lexical scope is inspected.
        load_position: Deterministic source position of the later load.
        scope_index: Node and closure ownership for the current module.
        events_by_scope_and_name: Sorted imports and invalidations by scope/name.
        bound_names: Names considered local in each scope, even if bound later.

    Returns:
        Active import binding, or None for unbound, shadowed, or rebound names.
    """
    current_scope_id: int | None = scope_index.scope_by_node.get(id(load_node))
    # Walk outward until one lexical scope owns the loaded identifier.
    while current_scope_id is not None:
        scope_name = (current_scope_id, name)
        # A local name prevents fallback to an outer import after rebinding.
        if scope_name in bound_names:
            binding_events = events_by_scope_and_name.get(scope_name, [])
            # Only imports/rebinds before this expression can affect its value, and
            # a rebind the user's control flow may skip cannot prove the earlier
            # import is unreachable here. Keeping it would advise deleting a
            # producer the not-taken path still loads.
            prior_events = [
                event
                for event in binding_events
                if event.position < load_position
                and not (event.binding is None and event.is_conditional)
            ]
            # Class bodies resolve earlier loads outward before a later class assignment.
            if not prior_events:
                if isinstance(scope_index.scope_nodes.get(current_scope_id), ast.ClassDef):
                    current_scope_id = scope_index.parent_by_scope.get(current_scope_id)
                    continue
                # Function and comprehension locals apply across their complete scope.
                return None
            return prior_events[-1].binding
        current_scope_id = scope_index.parent_by_scope.get(current_scope_id)
    return None


def _record_loaded_candidate(
    binding: _ImportBinding,
    function_name: str,
    candidate_keys: frozenset[PrivateFunctionKey],
    live_keys: set[PrivateFunctionKey],
    ambiguous_keys: set[PrivateFunctionKey],
) -> None:
    """Classify one actual load as uniquely live, ambiguous, or irrelevant.

    Args:
        binding: Active import binding selected at the load position.
        function_name: Private producer name loaded by the consumer.
        candidate_keys: Eligible producer findings from the current project scan.
        live_keys: Mutable set receiving uniquely proved liveness.
        ambiguous_keys: Mutable set receiving duplicate-module evidence.

    Returns:
        None; relevant candidate keys are added to one evidence set.
    """
    # Only producer modules that define this candidate can affect its finding.
    matching_keys = [
        (module_path, function_name)
        for module_path in binding.module_paths
        if (module_path, function_name) in candidate_keys
    ]
    # Exactly one resolved module is sufficient positive liveness evidence.
    if len(binding.module_paths) == 1:
        live_keys.update(matching_keys)
        return
    # Multiple scanned targets cannot identify which producer the user will import.
    if len(binding.module_paths) > 1:
        ambiguous_keys.update(matching_keys)


def _attribute_chain(node: ast.Attribute) -> tuple[ast.Name | None, tuple[str, ...]]:
    """Split a loaded attribute into its root Name and ordered attribute parts.

    Args:
        node: Outermost attribute load from the user's expression.

    Returns:
        Root identifier plus attributes, or ``(None, ())`` for dynamic roots.
    """
    attributes: list[str] = []
    current: ast.AST = node
    # Walk from the outer private attribute back toward the imported root name.
    while isinstance(current, ast.Attribute):
        attributes.append(current.attr)
        current = current.value
    # Calls, subscripts, and other dynamic roots are not static import evidence.
    if not isinstance(current, ast.Name):
        return None, ()
    attributes.reverse()
    return current, tuple(attributes)


def _source_position(node: ast.AST, sequence: int) -> tuple[int, int, int]:
    """Return a stable source-order key for imports, rebinds, and loads.

    Args:
        node: Parsed source node; synthetic nodes may have no line information.
        sequence: In-memory traversal order used only as a final tie-breaker.

    Returns:
        Line, column, and sequence tuple; missing positions sort at zero.
    """
    return (
        int(getattr(node, "lineno", 0)),
        int(getattr(node, "col_offset", 0)),
        sequence,
    )


def _normalized_path(file_path: str) -> str:
    """Normalize a finding path to the slash-separated resolver form.

    Args:
        file_path: User-visible display path; empty text stays empty.

    Returns:
        Slash-separated path without a leading ``./`` marker.
    """
    normalized = file_path.replace("\\", "/")
    # Discovery normally removes this prefix; hand-built tests may retain it.
    if normalized.startswith("./"):
        return normalized[2:]
    return normalized


def _module_suffixes(file_path: str) -> tuple[str, ...]:
    """Return every importable dotted suffix represented by one Python path.

    Args:
        file_path: Normalized scanned ``.py`` path; empty is valid but unresolved.

    Returns:
        Dotted module suffixes from longest to shortest; invalid parts are skipped.
    """
    module_parts = list(PurePosixPath(file_path).with_suffix("").parts)
    # Package initializers represent their directory rather than ``.__init__``.
    if module_parts and module_parts[-1] == "__init__":
        module_parts.pop()
    suffixes: list[str] = []
    # Dropping leading source-root parts supports src, flat, and monorepo layouts.
    for start_index in range(len(module_parts)):
        suffix_parts = module_parts[start_index:]
        # Filesystem-only segments cannot participate in a Python dotted import.
        if not suffix_parts or not all(part.isidentifier() for part in suffix_parts):
            continue
        suffixes.append(".".join(suffix_parts))
    return tuple(suffixes)
