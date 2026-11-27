"""Track bounded user-controlled values within one parsed Python scope.

Security rules use this helper while turning a user's endpoint into findings.
The finite sources cover request attributes, ``request.get_json()``, and
FastAPI parameters. ``get``/``getlist`` preserve an already-tainted receiver.
Consumer sanitisers win, reassignment can clear taint, and branches join safely.
Every other call remains untainted under ADR-017's conservative posture.
"""

import ast
from dataclasses import dataclass, field

from gruffpy.rule.security._security_node_helper import call_target_name, imported_module_names

_REQUEST_ATTRS: frozenset[str] = frozenset({"json", "form", "args", "GET", "POST", "data", "query_params", "values"})
_DIRECT_REQUEST_SOURCE_METHODS: frozenset[str] = frozenset({"get_json"})
_REQUEST_ACCESSOR_METHODS: frozenset[str] = frozenset({"get", "getlist"})
_FASTAPI_PARAM_SOURCES: frozenset[str] = frozenset({"Query", "Body", "Path", "Form", "Header", "Cookie", "File"})


@dataclass
class TaintMap:
    """Records which expression nodes evaluate to a tainted value.

    Tainted-ness is decided when the visitor reaches each expression in
    its lexical position, with the tainted-name set active at that point.

    Attributes:
        _tainted_expr_ids: ``id(expr)`` values for expressions the
            analyser concluded were tainted.
    """

    _tainted_expr_ids: set[int] = field(default_factory=set)

    def mark(self, expr: ast.expr) -> None:
        """Record the expression as tainted at its lexical position.

        Args:
            expr: Expression node to mark as tainted.

        Returns:
            None; adds the expression identity to this map's tainted set.
        """
        self._tainted_expr_ids.add(id(expr))

    def is_tainted(self, expr: ast.expr) -> bool:
        """Return whether the expression node was concluded tainted.

        Args:
            expr: Expression node to query.

        Returns:
            True if the analyser marked the expression as tainted.
        """
        return id(expr) in self._tainted_expr_ids


class TaintAnalyser:
    """Per-tree intra-procedural taint analyser.

    Consumer rules construct one instance with their sanitiser
    allowlist, call :meth:`analyse_tree` once per source file, and query
    the returned :class:`TaintMap` at every sink they walk.
    """

    def __init__(self, sanitisers: frozenset[str]) -> None:
        """Configure the analyser with a consumer-rule sanitiser allowlist.

        Args:
            sanitisers: Final names of bare or name-rooted dotted call targets to treat as untainted, such as secure_filename.

        Returns:
            None; stores the allowlist on this analyser.
        """
        self._sanitisers = sanitisers

    def analyse_tree(self, tree: ast.AST) -> TaintMap:
        """Analyse a module and build a map for querying the taint of its expression nodes.

        Args:
            tree: AST to analyse; only module nodes are traversed.

        Returns:
            A fresh taint map; empty for a non-module tree or when no expression is marked tainted.
        """
        taint_map = TaintMap()
        if not isinstance(tree, ast.Module):
            return taint_map
        walker = _ScopeWalker(taint_map, self._sanitisers, imported_module_names(tree))
        walker.walk_body(tree.body, tainted=set())
        return taint_map


class _ScopeWalker:
    """Track user-controlled names while walking one lexical scope.

    Security consumers receive the resulting expression map for their sink checks.
    Users reach this walk after the parser accepts an endpoint or module body.
    """

    def __init__(
        self,
        taint_map: TaintMap,
        sanitisers: frozenset[str],
        imported_modules: frozenset[str],
    ) -> None:
        self._map = taint_map
        self._sanitisers = sanitisers
        self._imported_modules = imported_modules

    def walk_body(self, body: list[ast.stmt], tainted: set[str]) -> set[str]:
        """Walk statements in order, updating the supplied name set and recording tainted expressions in the shared map.

        Args:
            body: Statement list to walk.
            tainted: Incoming tainted names, updated in place to reflect the names tainted on exit.

        Returns:
            The (mutated) tainted-name set after the body.
        """
        for stmt in body:
            self._walk_stmt(stmt, tainted)
        return tainted

    def _walk_stmt(self, stmt: ast.stmt, tainted: set[str]) -> None:
        """Update taint state for a statement or visit its remaining expressions.

        Supported scopes, assignments and branches receive their dedicated state handling.

        Args:
            stmt: Statement whose supported effects and expressions are inspected.
            tainted: Current tainted names, mutated by supported statement handlers.

        Returns:
            None; may update the supplied name set and record expression identities in the shared taint map.
        """
        if self._did_handle_scope_or_assignment(stmt, tainted):
            return
        if self._did_handle_branching(stmt, tainted):
            return
        self._visit_expressions_in(stmt, tainted)

    def _did_handle_scope_or_assignment(self, stmt: ast.stmt, tainted: set[str]) -> bool:
        """Handle supported nested scopes and assignments, recording tainted expressions in the shared map.

        Nested scopes use fresh name sets; defining a function or class clears its name in the enclosing set.

        Args:
            stmt: Statement checked for a function, class or supported assignment form.
            tainted: Enclosing tainted-name set, updated in place when a supported statement is handled.

        Returns:
            True when this handler processed the statement; False when another handler must inspect it.
        """
        if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef):
            self._walk_function(stmt)
            tainted.discard(stmt.name)
            return True
        if isinstance(stmt, ast.ClassDef):
            self.walk_body(stmt.body, set())
            tainted.discard(stmt.name)
            return True
        if isinstance(stmt, ast.Assign):
            self._walk_assign(stmt, tainted)
            return True
        if isinstance(stmt, ast.AnnAssign):
            self._walk_ann_assign(stmt, tainted)
            return True
        if isinstance(stmt, ast.AugAssign):
            self._walk_aug_assign(stmt, tainted)
            return True
        return False

    def _did_handle_branching(self, stmt: ast.stmt, tainted: set[str]) -> bool:
        """Handle supported conditional, loop and try statements, recording tainted expressions in the shared map.

        Args:
            stmt: Statement checked for a supported branching construct.
            tainted: Incoming tainted names, replaced in place with the branch handler's joined result.

        Returns:
            True when a branch handler processed the statement; False for other statement forms.
        """
        if isinstance(stmt, ast.If):
            self._walk_if(stmt, tainted)
            return True
        if isinstance(stmt, ast.For | ast.AsyncFor):
            self._walk_for(stmt, tainted)
            return True
        if isinstance(stmt, ast.While):
            self._walk_while(stmt, tainted)
            return True
        if isinstance(stmt, ast.Try):
            self._walk_try(stmt, tainted)
            return True
        return False

    def _walk_function(self, function: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Walk a function with fresh taint state seeded by recognized request parameters.

        Expressions marked in the function are added to the shared taint map.

        Args:
            function: Function whose parameter syntax seeds a fresh name set before its body is visited.

        Returns:
            None; adds marked expression identities to the shared taint map.
        """
        scope: set[str] = set()
        scope.update(_fastapi_param_sources(function))
        self.walk_body(function.body, scope)

    def _walk_assign(self, stmt: ast.Assign, tainted: set[str]) -> None:
        """Visit an assigned value and propagate its taint to supported target names.

        Args:
            stmt: Plain assignment whose value is inspected before any target state changes.
            tainted: Current tainted names, updated or cleared for each supported target in place.

        Returns:
            None; records tainted value expressions in the shared map and updates the supplied name set.
        """
        self._visit_expr(stmt.value, tainted)
        value_tainted = self._is_tainted(stmt.value, tainted)
        for target in stmt.targets:
            self._apply_assignment(target, value_tainted, tainted)

    def _walk_ann_assign(self, stmt: ast.AnnAssign, tainted: set[str]) -> None:
        """Propagate an annotated assignment's value taint to supported target names.

        An annotation without a value clears the supported target names from taint state.

        Args:
            stmt: Annotated assignment whose optional value is inspected when present.
            tainted: Current tainted names, mutated to reflect the value or its absence.

        Returns:
            None; records tainted value expressions in the shared map and updates the supplied name set.
        """
        if stmt.value is not None:
            self._visit_expr(stmt.value, tainted)
            value_tainted = self._is_tainted(stmt.value, tainted)
        else:
            value_tainted = False
        self._apply_assignment(stmt.target, value_tainted, tainted)

    def _walk_aug_assign(self, stmt: ast.AugAssign, tainted: set[str]) -> None:
        """Mark a directly named augmented-assignment target when its right side is tainted.

        Existing tainted names are retained when the right side does not add taint.

        Args:
            stmt: Augmented assignment whose right-side expressions are visited.
            tainted: Current tainted names, extended in place for a tainted right side and direct name target.

        Returns:
            None; records tainted right-side expressions in the shared map and may extend the supplied name set.
        """
        self._visit_expr(stmt.value, tainted)
        rhs_tainted = self._is_tainted(stmt.value, tainted)
        if rhs_tainted and isinstance(stmt.target, ast.Name):
            tainted.add(stmt.target.id)

    def _walk_if(self, stmt: ast.If, tainted: set[str]) -> None:
        """Visit both conditional branches and retain their shared tainted names.

        Without an else branch, only incoming names still tainted after the if body survive.

        Args:
            stmt: Conditional whose test is visited before both bodies are walked from separate incoming-state copies.
            tainted: Incoming names, replaced in place by the intersection of both branch exit sets.

        Returns:
            None; records tainted expressions in the shared map and replaces the supplied name set with the joined result.
        """
        self._visit_expr(stmt.test, tainted)
        if_tainted = self.walk_body(stmt.body, set(tainted))
        else_tainted = self.walk_body(stmt.orelse, set(tainted))
        joined = if_tainted & else_tainted
        tainted.clear()
        tainted.update(joined)

    def _walk_for(self, stmt: ast.For | ast.AsyncFor, tainted: set[str]) -> None:
        """Visit a for loop and retain taint shared by its incoming, body and else states.

        The iterable is visited without assigning its taint to the loop target.

        Args:
            stmt: For or async-for loop whose iterable, body and else expressions are inspected.
            tainted: Incoming names, replaced in place by their intersection with the body and else exit sets.

        Returns:
            None; records tainted expressions in the shared map and replaces the supplied name set with the joined result.
        """
        self._visit_expr(stmt.iter, tainted)
        body_tainted = self.walk_body(stmt.body, set(tainted))
        orelse_tainted = self.walk_body(stmt.orelse, set(tainted))
        joined = body_tainted & orelse_tainted & tainted
        tainted.clear()
        tainted.update(joined)

    def _walk_while(self, stmt: ast.While, tainted: set[str]) -> None:
        """Visit a while loop and retain taint shared by its incoming, body and else states.

        Args:
            stmt: Loop whose test is visited before its body and else use separate incoming-state copies.
            tainted: Incoming names, replaced in place by their intersection with the body and else exit sets.

        Returns:
            None; records tainted expressions in the shared map and replaces the supplied name set with the joined result.
        """
        self._visit_expr(stmt.test, tainted)
        body_tainted = self.walk_body(stmt.body, set(tainted))
        orelse_tainted = self.walk_body(stmt.orelse, set(tainted))
        joined = body_tainted & orelse_tainted & tainted
        tainted.clear()
        tainted.update(joined)

    def _walk_try(self, stmt: ast.Try, tainted: set[str]) -> None:
        """Join try-flow taint by intersecting the final-body result with handler exits.

        The else body follows the try-body state; the final body follows that result, while handlers start from incoming state.

        Args:
            stmt: Try statement whose bodies and handlers are visited using the supported state-joining model.
            tainted: Incoming names, replaced in place with the computed intersection of exit states.

        Returns:
            None; records tainted expressions in the shared map and replaces the supplied name set with the joined result.
        """
        body_tainted = self.walk_body(stmt.body, set(tainted))
        handler_sets: list[set[str]] = []
        for handler in stmt.handlers:
            handler_sets.append(self.walk_body(handler.body, set(tainted)))
        orelse_tainted = self.walk_body(stmt.orelse, set(body_tainted))
        finally_tainted = self.walk_body(stmt.finalbody, set(orelse_tainted))
        joined = finally_tainted
        for handler_set in handler_sets:
            joined &= handler_set
        tainted.clear()
        tainted.update(joined)

    def _apply_assignment(
        self,
        target: ast.expr,
        value_tainted: bool,
        tainted: set[str],
    ) -> None:
        """Add or clear the supported names in an assignment target.

        Args:
            target: Assignment target. Direct names count, including through nested tuples and lists. Starred and other targets contribute no names.
            value_tainted: Whether collected target names should be added rather than removed.
            tainted: Current tainted names, updated in place for the collected targets.

        Returns:
            None; updates the supplied tainted-name set.
        """
        names = _names_from_target(target)
        if value_tainted:
            tainted.update(names)
            return
        tainted.difference_update(names)

    def _visit_expressions_in(self, stmt: ast.stmt, tainted: set[str]) -> None:
        """Visit a statement's child subtrees to record tainted expressions.

        This traversal records expression identities without applying statement assignment or branch semantics.

        Args:
            stmt: Statement whose direct children start recursive expression visits.
            tainted: Current name state read when classifying expressions; not mutated by this traversal.

        Returns:
            None; records matching expression identities in the shared taint map.
        """
        for child in ast.iter_child_nodes(stmt):
            self._visit_expr(child, tainted)

    def _visit_expr(self, node: ast.AST, tainted: set[str]) -> None:
        """Record supported tainted expressions throughout an AST subtree.

        Matching expression identities are added to the shared map before their child nodes are visited.

        Args:
            node: AST subtree whose expressions and descendants are inspected.
            tainted: Current name state read during classification; not mutated by this traversal.

        Returns:
            None; adds matching expression identities to the shared taint map.
        """
        if isinstance(node, ast.expr) and self._is_tainted(node, tainted):
            self._map.mark(node)
        for child in ast.iter_child_nodes(node):
            self._visit_expr(child, tainted)

    def _is_tainted(self, expr: ast.expr, tainted: set[str]) -> bool:
        """Classify an expression using the supported taint sources and propagation shapes.

        Args:
            expr: Expression checked by the primitive, compound or call classifier.
            tainted: Current names treated as tainted, read without mutation.

        Returns:
            True when a supported rule marks the value tainted; False for other shapes or unmarked values.
        """
        if isinstance(expr, ast.Name | ast.Attribute | ast.Subscript):
            return self._is_primitive_tainted(expr, tainted)
        if isinstance(expr, ast.BinOp | ast.JoinedStr | ast.FormattedValue | ast.IfExp):
            return self._is_compound_tainted(expr, tainted)
        if isinstance(expr, ast.Call):
            return self._is_call_tainted(expr, tainted)
        return False

    def _is_primitive_tainted(
        self,
        expr: ast.Name | ast.Attribute | ast.Subscript,
        tainted: set[str],
    ) -> bool:
        """Check taint on names, attribute receivers and subscript components.

        Recognized request attributes supply taint even when their receiver name is not in the current set.

        Args:
            expr: Name, attribute or subscript whose supported source and component rules are checked.
            tainted: Current tainted names used when checking the expression and its components.

        Returns:
            True for a marked name, recognized request source or propagated component; False otherwise.
        """
        if isinstance(expr, ast.Name):
            return expr.id in tainted
        if isinstance(expr, ast.Attribute):
            if _is_request_source(expr, self._imported_modules):
                return True
            return self._is_tainted(expr.value, tainted)
        return self._is_tainted(expr.value, tainted) or self._is_tainted(expr.slice, tainted)

    def _is_compound_tainted(
        self,
        expr: ast.BinOp | ast.JoinedStr | ast.FormattedValue | ast.IfExp,
        tainted: set[str],
    ) -> bool:
        """Propagate taint through addition, percent operations, f-strings and conditional expressions.

        Conditional expressions use their result branches rather than their condition to determine value taint.

        Args:
            expr: Binary, joined-string, formatted-value or conditional expression to classify.
            tainted: Current tainted names used while classifying the supported value components.

        Returns:
            True when a supported value component is tainted; False for other binary operators or untainted components.
        """
        if isinstance(expr, ast.BinOp):
            if not isinstance(expr.op, ast.Add | ast.Mod):
                return False
            return self._is_tainted(expr.left, tainted) or self._is_tainted(expr.right, tainted)
        if isinstance(expr, ast.JoinedStr):
            return any(self._is_tainted(value, tainted) for value in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self._is_tainted(expr.value, tainted)
        return self._is_tainted(expr.body, tainted) or self._is_tainted(expr.orelse, tainted)

    def _is_call_tainted(self, call: ast.Call, tainted_names: set[str]) -> bool:
        """Return whether a supported call exposes user-controlled data.

        Args:
            call: Call from the user's source being evaluated.
            tainted_names: Names currently known as user-controlled; empty means none.

        Returns:
            True when a bounded call preserves taint; false keeps the call out of findings.
        """
        call_target = call_target_name(call)
        # A named sanitizer wins; None means a dynamic call cannot match the allowlist.
        if call_target is not None and call_target.split(".")[-1] in self._sanitisers:
            return False
        # Supported request accessors reflect user input without opening all unknown calls.
        if self._is_user_request_accessor_tainted(call, tainted_names):
            return True
        # Users can interpolate request values through the documented string format call.
        if isinstance(call.func, ast.Attribute) and call.func.attr == "format":
            # A tainted template keeps the formatted result user-controlled.
            if self._is_tainted(call.func.value, tainted_names):
                return True
            # Any tainted format argument makes the text shown to the sink user-controlled.
            return any(self._is_tainted(arg, tainted_names) for arg in call.args)
        return False

    def _is_user_request_accessor_tainted(
        self,
        request_accessor_call: ast.Call,
        tainted_names: set[str],
    ) -> bool:
        """Recognise only direct JSON reads or accessors on tainted request data.

        Args:
            request_accessor_call: User call that may read a request value.
            tainted_names: Names already marked as user-controlled. An empty set still allows recognized request sources to qualify.

        Returns:
            True for get_json on a recognized request object or get or getlist on a tainted receiver.
            False leaves the call subject to the other call taint rules.
        """
        # Bare functions have no receiver that can be tied to the user's request data.
        if not isinstance(request_accessor_call.func, ast.Attribute):
            return False
        accessor_method = request_accessor_call.func.attr
        accessor_receiver = request_accessor_call.func.value
        # Flask users may read their JSON body directly from the recognised request object.
        if accessor_method in _DIRECT_REQUEST_SOURCE_METHODS:
            return _is_request_object(accessor_receiver, self._imported_modules)
        # Methods such as pop fall outside the request accessor rules even when the receiver is tainted.
        if accessor_method not in _REQUEST_ACCESSOR_METHODS:
            return False
        return self._is_tainted(accessor_receiver, tainted_names)


def _is_request_source(
    request_attribute: ast.Attribute,
    imported_modules: frozenset[str],
) -> bool:
    """Return whether an attribute is one of the finite request data sources.

    Args:
        request_attribute: Attribute expression checked for a listed source name and a recognized request receiver.
        imported_modules: Names bound by an import in the same file.

    Returns:
        True for a supported source on a recognized request receiver; false leaves other taint propagation to the caller.
    """
    # Unlisted attributes add no request-source taint; their receiver may still carry taint.
    if request_attribute.attr not in _REQUEST_ATTRS:
        return False
    return _is_request_object(request_attribute.value, imported_modules)


def _is_request_object(request_receiver: ast.expr, imported_modules: frozenset[str]) -> bool:
    """Recognize receiver spellings that taint analysis treats as request objects.

    Args:
        request_receiver: Receiver before a request attribute or direct method.
        imported_modules: Names accepted as the base of a request attribute based solely on the file's import spellings.

    Returns:
        True for request, self.request or a request attribute on an import-bound name. False for other receiver shapes.
    """
    # The bare name request qualifies even when the file has no matching import.
    if isinstance(request_receiver, ast.Name):
        return request_receiver.id == "request"
    if not isinstance(request_receiver, ast.Attribute) or request_receiver.attr != "request":
        return False
    if not isinstance(request_receiver.value, ast.Name):
        return False
    # Class-based handlers can expose the same user request as self.request.
    if request_receiver.value.id == "self":
        return True
    # Import-bound receivers qualify by spelling; this does not establish their runtime framework identity.
    return request_receiver.value.id in imported_modules


def _names_from_target(target: ast.expr) -> set[str]:
    """Collect assigned names from direct names and nested tuple or list targets.

    Args:
        target: Assignment target recursively inspected through tuple and list elements.

    Returns:
        Supported target names, or an empty set for attributes, subscripts, starred targets and other shapes.
    """
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        names: set[str] = set()
        for elt in target.elts:
            names.update(_names_from_target(elt))
        return names
    return set()


def _fastapi_param_sources(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Find parameters whose annotations or defaults match supported FastAPI source spellings.

    Args:
        function: Function definition whose parameters to inspect.

    Returns:
        Recognized positional-only, positional and keyword-only parameter names; empty when none match. Variadic parameters are ignored.
    """
    names: set[str] = set()
    for arg in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs):
        if _is_fastapi_source_annotation(arg.annotation):
            names.add(arg.arg)
    positional_args = list(function.args.posonlyargs) + list(function.args.args)
    if function.args.defaults:
        offset = len(positional_args) - len(function.args.defaults)
        for arg, default in zip(positional_args[offset:], function.args.defaults, strict=True):
            if _is_fastapi_source_default(default):
                names.add(arg.arg)
    for kw_arg, kw_default in zip(function.args.kwonlyargs, function.args.kw_defaults, strict=True):
        if kw_default is None:
            continue
        if _is_fastapi_source_default(kw_default):
            names.add(kw_arg.arg)
    return names


def _is_fastapi_source_annotation(annotation: ast.expr | None) -> bool:
    """Recognize supported request-source spellings in parameter annotations.

    Args:
        annotation: Optional annotation checked as a recognized bare name or supported subscript payload.

    Returns:
        True when supported annotation syntax matches; False for None or other shapes, without resolving imports.
    """
    if annotation is None:
        return False
    if isinstance(annotation, ast.Name):
        return annotation.id in _FASTAPI_PARAM_SOURCES
    if isinstance(annotation, ast.Subscript):
        return _has_fastapi_source_in_subscript(annotation)
    return False


def _has_fastapi_source_in_subscript(node: ast.Subscript) -> bool:
    """Look for a recognized request-source marker in a subscript payload.

    Args:
        node: Annotation subscript whose single payload or tuple items are checked without interpreting its outer name.

    Returns:
        True when a supported payload item matches; False when no item qualifies.
    """
    payload = node.slice
    if isinstance(payload, ast.Tuple):
        return any(_is_fastapi_source_subscript_inner(elt) for elt in payload.elts)
    return _is_fastapi_source_subscript_inner(payload)


def _is_fastapi_source_subscript_inner(node: ast.expr) -> bool:
    """Recognize a request-source name or call in an annotation subscript payload.

    Args:
        node: Payload item checked by its bare name or terminal call spelling without resolving bindings.

    Returns:
        True for a recognized source spelling; False for other names or expression shapes.
    """
    if isinstance(node, ast.Name):
        return node.id in _FASTAPI_PARAM_SOURCES
    if isinstance(node, ast.Call):
        target = call_target_name(node)
        return target is not None and target.split(".")[-1] in _FASTAPI_PARAM_SOURCES
    return False


def _is_fastapi_source_default(default: ast.expr | None) -> bool:
    """Recognize a request-source call used as a parameter default.

    Args:
        default: Optional default checked for a call with a recognized terminal name.

    Returns:
        True when the default call spelling matches; False for None or unsupported expressions, without resolving imports.
    """
    if default is None or not isinstance(default, ast.Call):
        return False
    target = call_target_name(default)
    return target is not None and target.split(".")[-1] in _FASTAPI_PARAM_SOURCES
