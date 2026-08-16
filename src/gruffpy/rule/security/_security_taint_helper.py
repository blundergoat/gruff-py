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

_REQUEST_ATTRS: frozenset[str] = frozenset(
    {"json", "form", "args", "GET", "POST", "data", "query_params", "values"}
)
_DIRECT_REQUEST_SOURCE_METHODS: frozenset[str] = frozenset({"get_json"})
_REQUEST_ACCESSOR_METHODS: frozenset[str] = frozenset({"get", "getlist"})
_FASTAPI_PARAM_SOURCES: frozenset[str] = frozenset(
    {"Query", "Body", "Path", "Form", "Header", "Cookie", "File"}
)


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
        """Record *expr* as tainted at its lexical position.

        Args:
            expr: Expression node to mark as tainted.
        """
        self._tainted_expr_ids.add(id(expr))

    def is_tainted(self, expr: ast.expr) -> bool:
        """Return whether *expr* was concluded tainted.

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
            sanitisers: Dotted call-target leaf names whose return value
                is treated as untainted regardless of argument taint
                (e.g., ``"secure_filename"`` for path-traversal).
        """
        self._sanitisers = sanitisers

    def analyse_tree(self, tree: ast.AST) -> TaintMap:
        """Walk *tree*, returning a populated taint map.

        Args:
            tree: Module (or other) AST to analyse.

        Returns:
            Map listing every expression node concluded tainted.
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
        """Walk a list of statements in order, mutating *tainted* in place.

        Args:
            body: Statement list to walk.
            tainted: Tainted-name set entering this body. Mutated to
                reflect the names tainted on exit.

        Returns:
            The (mutated) tainted-name set after the body.
        """
        for stmt in body:
            self._walk_stmt(stmt, tainted)
        return tainted

    def _walk_stmt(self, stmt: ast.stmt, tainted: set[str]) -> None:
        if self._did_handle_scope_or_assignment(stmt, tainted):
            return
        if self._did_handle_branching(stmt, tainted):
            return
        self._visit_expressions_in(stmt, tainted)

    def _did_handle_scope_or_assignment(self, stmt: ast.stmt, tainted: set[str]) -> bool:
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
        scope: set[str] = set()
        scope.update(_fastapi_param_sources(function))
        self.walk_body(function.body, scope)

    def _walk_assign(self, stmt: ast.Assign, tainted: set[str]) -> None:
        self._visit_expr(stmt.value, tainted)
        value_tainted = self._is_tainted(stmt.value, tainted)
        for target in stmt.targets:
            self._apply_assignment(target, value_tainted, tainted)

    def _walk_ann_assign(self, stmt: ast.AnnAssign, tainted: set[str]) -> None:
        if stmt.value is not None:
            self._visit_expr(stmt.value, tainted)
            value_tainted = self._is_tainted(stmt.value, tainted)
        else:
            value_tainted = False
        self._apply_assignment(stmt.target, value_tainted, tainted)

    def _walk_aug_assign(self, stmt: ast.AugAssign, tainted: set[str]) -> None:
        self._visit_expr(stmt.value, tainted)
        rhs_tainted = self._is_tainted(stmt.value, tainted)
        if rhs_tainted and isinstance(stmt.target, ast.Name):
            tainted.add(stmt.target.id)

    def _walk_if(self, stmt: ast.If, tainted: set[str]) -> None:
        self._visit_expr(stmt.test, tainted)
        if_tainted = self.walk_body(stmt.body, set(tainted))
        else_tainted = self.walk_body(stmt.orelse, set(tainted))
        joined = if_tainted & else_tainted
        tainted.clear()
        tainted.update(joined)

    def _walk_for(self, stmt: ast.For | ast.AsyncFor, tainted: set[str]) -> None:
        self._visit_expr(stmt.iter, tainted)
        body_tainted = self.walk_body(stmt.body, set(tainted))
        orelse_tainted = self.walk_body(stmt.orelse, set(tainted))
        joined = body_tainted & orelse_tainted & tainted
        tainted.clear()
        tainted.update(joined)

    def _walk_while(self, stmt: ast.While, tainted: set[str]) -> None:
        self._visit_expr(stmt.test, tainted)
        body_tainted = self.walk_body(stmt.body, set(tainted))
        orelse_tainted = self.walk_body(stmt.orelse, set(tainted))
        joined = body_tainted & orelse_tainted & tainted
        tainted.clear()
        tainted.update(joined)

    def _walk_try(self, stmt: ast.Try, tainted: set[str]) -> None:
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
        names = _names_from_target(target)
        if value_tainted:
            tainted.update(names)
            return
        tainted.difference_update(names)

    def _visit_expressions_in(self, stmt: ast.stmt, tainted: set[str]) -> None:
        for child in ast.iter_child_nodes(stmt):
            self._visit_expr(child, tainted)

    def _visit_expr(self, node: ast.AST, tainted: set[str]) -> None:
        if isinstance(node, ast.expr) and self._is_tainted(node, tainted):
            self._map.mark(node)
        for child in ast.iter_child_nodes(node):
            self._visit_expr(child, tainted)

    def _is_tainted(self, expr: ast.expr, tainted: set[str]) -> bool:
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
            tainted_names: Current user-controlled names; empty excludes assigned containers.

        Returns:
            True for the finite request seam; false leaves generic collection calls quiet.
        """
        # Bare functions have no receiver that can be tied to the user's request data.
        if not isinstance(request_accessor_call.func, ast.Attribute):
            return False
        accessor_method = request_accessor_call.func.attr
        accessor_receiver = request_accessor_call.func.value
        # Flask users may read their JSON body directly from the recognised request object.
        if accessor_method in _DIRECT_REQUEST_SOURCE_METHODS:
            return _is_request_object(accessor_receiver, self._imported_modules)
        # Other methods, such as pop, stay conservative even on a tainted request container.
        if accessor_method not in _REQUEST_ACCESSOR_METHODS:
            return False
        return self._is_tainted(accessor_receiver, tainted_names)


def _is_request_source(
    request_attribute: ast.Attribute,
    imported_modules: frozenset[str],
) -> bool:
    """Return whether an attribute is one of the finite request data sources.

    Args:
        request_attribute: Attribute a user read from a possible request object.
        imported_modules: Names bound by an import in the same file.

    Returns:
        True for a supported source; false prevents unrelated attributes becoming findings.
    """
    # Attributes outside the documented framework vocabulary are ordinary application data.
    if request_attribute.attr not in _REQUEST_ATTRS:
        return False
    return _is_request_object(request_attribute.value, imported_modules)


def _is_request_object(request_receiver: ast.expr, imported_modules: frozenset[str]) -> bool:
    """Return whether syntax identifies the framework request object.

    Args:
        request_receiver: Receiver before a request attribute or direct method.
        imported_modules: Names bound by an import in the same file, which
            separate a framework's module-level request proxy from an
            application object that merely owns a ``request`` attribute.

    Returns:
        True for ``request``, ``self.request``, and ``<imported>.request``.
    """
    # A typical endpoint imports and reads the framework's request object directly.
    if isinstance(request_receiver, ast.Name):
        return request_receiver.id == "request"
    if not isinstance(request_receiver, ast.Attribute) or request_receiver.attr != "request":
        return False
    if not isinstance(request_receiver.value, ast.Name):
        return False
    # Class-based handlers can expose the same user request as ``self.request``.
    if request_receiver.value.id == "self":
        return True
    # ``flask.request`` is the framework proxy only when this file imported the module;
    # an application object's ``other.request`` binds a parameter or local instead.
    return request_receiver.value.id in imported_modules


def _names_from_target(target: ast.expr) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, ast.Tuple | ast.List):
        names: set[str] = set()
        for elt in target.elts:
            names.update(_names_from_target(elt))
        return names
    return set()


def _fastapi_param_sources(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Return parameter names whose annotation or default marks them as a FastAPI source.

    Args:
        function: Function definition whose parameters to inspect.

    Returns:
        Set of parameter names recognised as FastAPI request sources.
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
    if annotation is None:
        return False
    if isinstance(annotation, ast.Name):
        return annotation.id in _FASTAPI_PARAM_SOURCES
    if isinstance(annotation, ast.Subscript):
        return _has_fastapi_source_in_subscript(annotation)
    return False


def _has_fastapi_source_in_subscript(node: ast.Subscript) -> bool:
    payload = node.slice
    if isinstance(payload, ast.Tuple):
        return any(_is_fastapi_source_subscript_inner(elt) for elt in payload.elts)
    return _is_fastapi_source_subscript_inner(payload)


def _is_fastapi_source_subscript_inner(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in _FASTAPI_PARAM_SOURCES
    if isinstance(node, ast.Call):
        target = call_target_name(node)
        return target is not None and target.split(".")[-1] in _FASTAPI_PARAM_SOURCES
    return False


def _is_fastapi_source_default(default: ast.expr | None) -> bool:
    if default is None or not isinstance(default, ast.Call):
        return False
    target = call_target_name(default)
    return target is not None and target.split(".")[-1] in _FASTAPI_PARAM_SOURCES
