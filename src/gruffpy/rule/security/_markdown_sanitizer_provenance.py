"""Prove which Markdown-link values are safe at each source position.

The rule builds this statement-ordered index once per scanned Python file.
Users reach it after configuring label and URL helpers; it recognizes only
those exact calls, bounded local assignments, and same-file import bindings.
"""

import ast
from typing import Literal

from gruffpy.rule.security._markdown_sanitizer_model import (
    _DEFAULT_QUOTE_TARGETS,
    _MARKDOWN_SLOTS,
    ExpressionSafety,
    MarkdownSlot,
    _CallableBindings,
    _FlowState,
    _safe,
    _TrackedValue,
    _unsafe,
    bound_names,
    combine_composed_safety,
    combine_expression_safety,
    function_parameter_names,
    is_quote_call_delimiter_safe,
    match_capture_names,
    merge_flow_states,
    target_root_name,
)
from gruffpy.rule.security._security_node_helper import call_target_name


class MarkdownSanitizerProvenance:
    """Index sanitizer proof state for every expression in one scanned file.

    The Markdown rule asks this index about expressions inside detected links.
    It never executes imports or follows calls, keeping the result predictable for users.
    """

    def __init__(self, label_targets: set[str], url_targets: set[str]) -> None:
        """Create an empty per-file index for the user's configured exact targets.

        Args:
            label_targets: Exact label helper names; empty means strict label mode.
            url_targets: Exact URL helper names; empty means strict URL mode.
        """
        self._label_targets = frozenset(label_targets)
        self._url_targets = frozenset(url_targets)
        self._state_by_expression: dict[int, _FlowState] = {}

    @classmethod
    def build(
        cls,
        tree: ast.Module,
        *,
        label_targets: set[str],
        url_targets: set[str],
    ) -> "MarkdownSanitizerProvenance":
        """Build the source-ordered proof index users rely on for one Python file.

        Args:
            tree: Parsed module; an empty body produces an empty proof index.
            label_targets: Exact helpers trusted for visible link text.
            url_targets: Exact helpers trusted for click targets.

        Returns:
            Queryable index; no recorded expression is treated as raw.
        """
        provenance = cls(label_targets, url_targets)
        module_state = _FlowState()
        provenance._scan_statements(
            tree.body,
            module_state,
            module_callables=module_state.callables.clone(),
            scope_kind="module",
        )
        return provenance

    def proof_for(self, expression: ast.expr, slot: MarkdownSlot) -> ExpressionSafety:
        """Explain whether one interpolated expression is safe for its rendered slot.

        Args:
            expression: AST value placed in the Markdown link.
            slot: Visible label or clickable URL slot selected by the rule.

        Returns:
            Safety proof; an unindexed expression is raw rather than silently safe.
        """
        snapshot = self._state_by_expression.get(id(expression))
        # Unindexed syntax cannot inherit a proof the scanner did not observe.
        if snapshot is None:
            return _unsafe("raw")
        return self._expression_safety(expression, slot, snapshot)

    def _scan_statements(
        self,
        statements: list[ast.stmt],
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState:
        """Advance proof state through statements in the order users wrote them.

        Args:
            statements: Current scope body; empty means no proof state changes.
            state: Starting proof state for this execution path.
            module_callables: Same-file imports visible to fresh nested functions.
            scope_kind: Current lexical scope used to isolate nested functions.

        Returns:
            State after the last reachable statement; unchanged for an empty body.
        """
        current_state = state
        # Each user statement may establish or invalidate the next link's proof.
        for statement in statements:
            current_state = self._scan_statement(
                statement,
                current_state,
                module_callables=module_callables,
                scope_kind=scope_kind,
            )
        return current_state

    def _scan_statement(
        self,
        statement: ast.stmt,
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState:
        """Route one statement to the bounded proof operation users expect.

        Args:
            statement: Next source statement in the current user scope.
            state: Proof state immediately before that statement.
            module_callables: Imports available when a nested function starts fresh.
            scope_kind: Current module, class, or function scope.

        Returns:
            Proof state visible to the following statement.
        """
        # Assignments and imports change the names a later link can trust.
        binding_result = self._scan_binding_statement(statement, state)
        # A handled binding returns the proof state visible to the user's next line.
        if binding_result is not None:
            return binding_result
        # Functions and classes start new user-visible rendering scopes.
        scope_result = self._scan_scope_statement(
            statement,
            state,
            module_callables=module_callables,
            scope_kind=scope_kind,
        )
        # A handled declaration keeps its outer-scope effects and isolates its body.
        if scope_result is not None:
            return scope_result
        # Branches merge only safety proofs available on every possible path.
        control_result = self._scan_control_statement(
            statement,
            state,
            module_callables=module_callables,
            scope_kind=scope_kind,
        )
        # A handled control statement returns the conservative user-visible join.
        if control_result is not None:
            return control_result
        self._record_statement_expressions(statement, state)
        return state

    def _scan_binding_statement(
        self,
        statement: ast.stmt,
        state: _FlowState,
    ) -> _FlowState | None:
        """Apply assignments/imports or return ``None`` for another statement family.

        Args:
            statement: Candidate binding statement from the user's source.
            state: Proof state to mutate after right-hand expressions are recorded.

        Returns:
            Updated state when handled; ``None`` asks the next dispatcher to inspect it.
        """
        # A normal assignment evaluates its value before replacing user names.
        if isinstance(statement, ast.Assign):
            self._record_expression(statement.value, state)
            # Every chained target receives the same bounded value proof.
            for assignment_target in statement.targets:
                self._assign_target(assignment_target, statement.value, state)
            return state
        # An annotated assignment without a value clears any earlier safety proof.
        if isinstance(statement, ast.AnnAssign):
            self._record_expression(statement.annotation, state)
            self._record_optional_expression(statement.value, state)
            # No value means the user declared a name but has not produced safe content.
            if statement.value is None:
                self._invalidate_target(statement.target, state)
            else:
                self._assign_target(statement.target, statement.value, state)
            return state
        # Augmented assignment combines an unknown prior runtime value and is never a proof.
        if isinstance(statement, ast.AugAssign):
            self._record_expression(statement.target, state)
            self._record_expression(statement.value, state)
            self._invalidate_target(statement.target, state)
            return state
        # An exact import establishes a local-to-canonical call spelling without execution.
        if isinstance(statement, ast.Import):
            # Each imported alias independently updates the callable roots users may invoke.
            for imported_alias in statement.names:
                self._apply_import(imported_alias, state)
            return state
        # A from-import maps the visible alias directly to its canonical callable target.
        if isinstance(statement, ast.ImportFrom):
            self._apply_from_import(statement, state)
            return state
        # Deleting a name removes both a prior safe value and callable proof.
        if isinstance(statement, ast.Delete):
            # Every deleted target becomes unproved for subsequent rendered links.
            for deleted_target in statement.targets:
                self._invalidate_target(deleted_target, state)
            return state
        return None

    def _scan_scope_statement(
        self,
        statement: ast.stmt,
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState | None:
        """Index nested scopes or return ``None`` when the statement is not a scope.

        Args:
            statement: Candidate function or class declaration.
            state: Outer proof state at declaration time.
            module_callables: Same-file imports available to fresh function scopes.
            scope_kind: Outer scope kind used for module-level helper declarations.

        Returns:
            Outer state after binding the declaration name, or ``None`` when unhandled.
        """
        # Functions evaluate headers outside, then analyze their body with fresh value state.
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._record_function_header(statement, state)
            visible_module_callables = (
                state.callables.clone() if scope_kind == "module" else module_callables.clone()
            )
            function_state = _FlowState(callables=visible_module_callables)
            # Parameters are user-controlled local bindings, even when they reuse import names.
            for parameter_name in function_parameter_names(statement.args):
                function_state.callables.shadow(parameter_name)
            self._scan_statements(
                statement.body,
                function_state,
                module_callables=visible_module_callables,
                scope_kind="function",
            )
            self._bind_declaration_name(statement.name, state, scope_kind)
            return state
        # Class bodies may contain methods, but class-local values do not flow into them.
        if isinstance(statement, ast.ClassDef):
            # Bases and decorators run in the outer user's current proof state.
            for header_expression in [*statement.bases, *statement.decorator_list]:
                self._record_expression(header_expression, state)
            visible_module_callables = (
                state.callables.clone() if scope_kind == "module" else module_callables.clone()
            )
            class_state = _FlowState(callables=visible_module_callables)
            self._scan_statements(
                statement.body,
                class_state,
                module_callables=visible_module_callables,
                scope_kind="class",
            )
            self._bind_declaration_name(statement.name, state, scope_kind)
            return state
        return None

    def _scan_control_statement(
        self,
        statement: ast.stmt,
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState | None:
        """Merge bounded branch/loop/with paths or return ``None`` when unhandled.

        Args:
            statement: Candidate control-flow statement from the user's source.
            state: Proof state before control flow diverges.
            module_callables: Same-file imports visible to nested functions.
            scope_kind: Current lexical scope for declarations inside branches.

        Returns:
            Conservatively merged state, or ``None`` for a simple statement.
        """
        # Both `if` outcomes must prove safety before a later rendered value is trusted.
        if isinstance(statement, ast.If):
            self._record_expression(statement.test, state)
            body_state = self._scan_statements(
                statement.body,
                state.clone(),
                module_callables=module_callables,
                scope_kind=scope_kind,
            )
            # Missing `else` means the user's original raw state is also possible.
            if statement.orelse:
                else_state = self._scan_statements(
                    statement.orelse,
                    state.clone(),
                    module_callables=module_callables,
                    scope_kind=scope_kind,
                )
            else:
                else_state = state.clone()
            return merge_flow_states([body_state, else_state])
        # A loop may execute zero times, so pre-loop state always participates in the join.
        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            return self._scan_loop_statement(
                statement,
                state,
                module_callables=module_callables,
                scope_kind=scope_kind,
            )
        # Context-manager targets are runtime values and cannot inherit sanitizer safety.
        if isinstance(statement, (ast.With, ast.AsyncWith)):
            with_state = state.clone()
            # Each `with` item is evaluated before its optional local target is bound.
            for with_item in statement.items:
                self._record_expression(with_item.context_expr, with_state)
                # A context manager without `as name` introduces no local value.
                if with_item.optional_vars is not None:
                    self._invalidate_target(with_item.optional_vars, with_state)
            return self._scan_statements(
                statement.body,
                with_state,
                module_callables=module_callables,
                scope_kind=scope_kind,
            )
        # Each `case` body is one path the user's subject can take, and none may match.
        if isinstance(statement, ast.Match):
            return self._scan_match_statement(
                statement,
                state,
                module_callables=module_callables,
                scope_kind=scope_kind,
            )
        # Try/except paths disagree unless every successful or handled path proves safety.
        # `except*` groups are a separate node type carrying the same handler shape.
        if isinstance(statement, (ast.Try, ast.TryStar)):
            return self._scan_try_statement(
                statement,
                state,
                module_callables=module_callables,
                scope_kind=scope_kind,
            )
        return None

    def _scan_loop_statement(
        self,
        statement: ast.For | ast.AsyncFor | ast.While,
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState:
        """Join a loop body with the pre-loop state a user reaches on zero iterations.

        The body is scanned once, not to a fixpoint. Dropping every proof the
        body can rebind before that single scan makes the result sound for any
        iteration count: a name proved safe before the loop and reassigned to a
        raw value inside it is uncertain at the top of the body, as it is on the
        user's second pass. Names the body proves before using them keep their
        proof, because the body scan re-establishes those in source order.

        Args:
            statement: `for`, `async for`, or `while` whose body may not run at all.
            state: Proof state before the loop header is evaluated.
            module_callables: Same-file imports visible to nested functions.
            scope_kind: Current lexical scope for declarations inside the body.

        Returns:
            State after the merged body and any `else` clause; an empty body still joins.
        """
        body_state = state.clone()
        # A `for` target takes a fresh runtime element each pass, so it proves nothing.
        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._record_expression(statement.iter, state)
            self._invalidate_target(statement.target, body_state)
        else:
            self._record_expression(statement.test, state)
        self._invalidate_loop_rebindings(statement.body, body_state)
        body_state = self._scan_statements(
            statement.body,
            body_state,
            module_callables=module_callables,
            scope_kind=scope_kind,
        )
        merged_loop_state = merge_flow_states([state.clone(), body_state])
        return self._scan_statements(
            statement.orelse,
            merged_loop_state,
            module_callables=module_callables,
            scope_kind=scope_kind,
        )

    def _invalidate_loop_rebindings(self, body: list[ast.stmt], state: _FlowState) -> None:
        """Drop proofs for every name a loop body can rebind, before scanning it once.

        Walks the body without descending into nested function, class, or lambda
        scopes: those bind their own names, while the declaration itself rebinds
        a name in the loop's scope. Missing a binding form here would leave the
        same loop-carried unsoundness this pre-pass exists to close.

        Args:
            body: Statements the user's loop repeats.
            state: Body-entry proof state mutated before the body scan.
        """
        pending: list[ast.AST] = list(body)
        while pending:
            node = pending.pop()
            # A declaration rebinds its own name; its body belongs to a separate scope.
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._invalidate_name(node.name, state)
                state.callables.shadow(node.name)
                continue
            # A lambda binds only its parameters, inside its own scope.
            if isinstance(node, ast.Lambda):
                continue
            self._invalidate_rebinding(node, state)
            pending.extend(ast.iter_child_nodes(node))

    def _invalidate_rebinding(self, node: ast.AST, state: _FlowState) -> None:
        """Invalidate the names one binding node introduces into the loop's scope.

        Args:
            node: Candidate binding node from inside a loop body.
            state: Proof state mutated for the body scan that follows.
        """
        if isinstance(node, ast.Assign):
            # Chained assignment rebinds every target from one value.
            for assigned_target in node.targets:
                self._invalidate_target(assigned_target, state)
            return
        if isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
            self._invalidate_target(node.target, state)
            return
        # A nested loop's target takes a fresh runtime element on every pass.
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._invalidate_target(node.target, state)
            return
        if isinstance(node, ast.withitem):
            # A context manager without `as name` introduces no local value.
            if node.optional_vars is not None:
                self._invalidate_target(node.optional_vars, state)
            return
        if isinstance(node, ast.ExceptHandler):
            # `except E as name` binds only when the user named the exception.
            if node.name is not None:
                self._invalidate_name(node.name, state)
                state.callables.shadow(node.name)
            return
        # A `match` case binds capture/star/mapping-rest names before its body
        # renders anything, so a later iteration can read that runtime piece of
        # the subject instead of a proof the pre-loop state held.
        if isinstance(node, ast.match_case):
            for capture_name in match_capture_names(node.pattern):
                self._invalidate_name(capture_name, state)
                state.callables.shadow(capture_name)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            self._invalidate_import_aliases(node, state)
            return
        if isinstance(node, ast.Delete):
            # Deleting a name inside the body removes a proof the pre-loop state held.
            for deleted_target in node.targets:
                self._invalidate_target(deleted_target, state)

    def _invalidate_import_aliases(
        self,
        node: ast.Import | ast.ImportFrom,
        state: _FlowState,
    ) -> None:
        """Invalidate names an import inside the loop body binds.

        A body-local import re-establishes its own canonical binding when the
        body scan reaches it, so this only removes trust the user's later
        spelling has not yet earned.

        Args:
            node: Import statement found inside the loop body.
            state: Proof state mutated for the body scan that follows.
        """
        for imported_alias in node.names:
            # `from x import *` binds names this walker cannot enumerate.
            if imported_alias.name == "*":
                continue
            bound_alias = imported_alias.asname or imported_alias.name.split(".", 1)[0]
            self._invalidate_name(bound_alias, state)
            state.callables.shadow(bound_alias)

    def _scan_match_statement(
        self,
        statement: ast.Match,
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState:
        """Merge every ``match`` case the user's value can take, plus the no-match path.

        Args:
            statement: `match` statement whose cases may each establish or destroy a proof.
            state: Proof state before the subject is evaluated.
            module_callables: Same-file imports visible to nested functions.
            scope_kind: Current lexical scope for declarations inside a case body.

        Returns:
            Conservative join; no case body means the pre-match state survives unchanged.
        """
        self._record_expression(statement.subject, state)
        # A subject matching no case leaves the proofs the user already had in force.
        possible_states = [state.clone()]
        # Only one case body runs, so every case must agree before a later link is trusted.
        for case in statement.cases:
            case_state = state.clone()
            # Captured names hold runtime pieces of the subject, never a proved sanitizer result.
            for capture_name in match_capture_names(case.pattern):
                self._invalidate_name(capture_name, case_state)
            # A guard runs once the pattern has bound, so it sees the captured names.
            self._record_optional_expression(case.guard, case_state)
            possible_states.append(
                self._scan_statements(
                    case.body,
                    case_state,
                    module_callables=module_callables,
                    scope_kind=scope_kind,
                )
            )
        return merge_flow_states(possible_states)

    def _scan_try_statement(
        self,
        statement: ast.Try | ast.TryStar,
        state: _FlowState,
        *,
        module_callables: _CallableBindings,
        scope_kind: Literal["module", "class", "function"],
    ) -> _FlowState:
        """Merge successful and caught user paths, then apply the shared finalizer.

        Args:
            statement: User `try` statement whose handlers may establish different values.
            state: Proof state before the attempted operation.
            module_callables: Same-file imports visible to nested functions.
            scope_kind: Current lexical scope for declarations in each path.

        Returns:
            State after all handlers and `finally`; empty handlers keep the success path.
        """
        successful_state = self._scan_statements(
            statement.body,
            state.clone(),
            module_callables=module_callables,
            scope_kind=scope_kind,
        )
        successful_state = self._scan_statements(
            statement.orelse,
            successful_state,
            module_callables=module_callables,
            scope_kind=scope_kind,
        )
        possible_states = [successful_state]
        # A user's exception path can start after any attempted statement, so use pre-try state.
        for handler in statement.handlers:
            handler_state = state.clone()
            self._record_optional_expression(handler.type, handler_state)
            # `except Error as problem` introduces an unproved runtime object.
            if handler.name is not None:
                self._invalidate_name(handler.name, handler_state)
            possible_states.append(
                self._scan_statements(
                    handler.body,
                    handler_state,
                    module_callables=module_callables,
                    scope_kind=scope_kind,
                )
            )
        merged_state = merge_flow_states(possible_states)
        return self._scan_statements(
            statement.finalbody,
            merged_state,
            module_callables=module_callables,
            scope_kind=scope_kind,
        )

    def _record_function_header(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        state: _FlowState,
    ) -> None:
        """Record defaults, annotations, and decorators evaluated outside a function body.

        Args:
            function: User function whose body will receive a fresh proof state.
            state: Outer state visible while Python evaluates the declaration header.
        """
        header_expressions: list[ast.expr | None] = [
            *function.decorator_list,
            *function.args.defaults,
            *function.args.kw_defaults,
            function.returns,
        ]
        # Each header expression belongs to the outer renderer, not the fresh function body.
        for header_expression in header_expressions:
            self._record_optional_expression(header_expression, state)

    def _record_statement_expressions(self, statement: ast.stmt, state: _FlowState) -> None:
        """Index expressions in a simple statement without changing user proof state.

        Args:
            statement: Return, expression, assertion, or unsupported bounded statement.
            state: Proof state visible while the statement evaluates.
        """
        self._record_expression_tree(statement, state)

    def _record_optional_expression(
        self,
        expression: ast.expr | None,
        state: _FlowState,
    ) -> None:
        """Index an optional expression; ``None`` means the user omitted that syntax.

        Args:
            expression: AST expression or ``None`` for an omitted annotation/value.
            state: Proof state visible while the expression evaluates.
        """
        # Omitted syntax cannot contain a user-rendered Markdown link.
        if expression is None:
            return
        self._record_expression(expression, state)

    def _record_expression(self, expression: ast.expr, state: _FlowState) -> None:
        """Snapshot proof state for an expression and all of its child values.

        Args:
            expression: User expression being evaluated at this source position.
            state: Proof state immediately before evaluation.
        """
        self._record_expression_tree(expression, state)

    def _record_expression_tree(self, node: ast.AST, state: _FlowState) -> None:
        """Index expressions recursively while respecting fresh lexical scopes.

        Args:
            node: Statement or expression whose evaluated children need snapshots.
            state: Proof state visible in the node's current lexical scope.
        """
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            self._record_comprehension(node, state)
            return
        if isinstance(node, ast.Lambda):
            # The lambda object is created in the outer scope, including its defaults.
            self._state_by_expression[id(node)] = state.clone()
            for default_expression in [*node.args.defaults, *node.args.kw_defaults]:
                self._record_optional_expression(default_expression, state)
            lambda_state = _FlowState(callables=state.callables.clone())
            for parameter_name in function_parameter_names(node.args):
                lambda_state.callables.shadow(parameter_name)
            self._record_expression(node.body, lambda_state)
            return
        # A walrus binds in the enclosing scope wherever an expression may appear,
        # so its target must gain or lose a proof exactly where Python assigns it.
        if isinstance(node, ast.NamedExpr):
            self._state_by_expression[id(node)] = state.clone()
            # Python evaluates the value before binding the user's target name.
            self._record_expression_tree(node.value, state)
            self._assign_target(node.target, node.value, state)
            return
        # Declarations encountered below an unsupported statement still own fresh bodies.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(node, ast.expr):
            self._state_by_expression[id(node)] = state.clone()
        for child in ast.iter_child_nodes(node):
            self._record_expression_tree(child, state)

    def _record_comprehension(
        self,
        expression: ast.ListComp | ast.SetComp | ast.DictComp | ast.GeneratorExp,
        state: _FlowState,
    ) -> None:
        """Index a comprehension in Python evaluation order with local targets.

        Args:
            expression: Comprehension whose leftmost iterable runs in the outer scope.
            state: Outer proof state captured by the comprehension.
        """
        self._state_by_expression[id(expression)] = state.clone()
        if not expression.generators:
            return
        first_generator, *remaining_generators = expression.generators
        # Python evaluates the leftmost iterable before opening the comprehension scope.
        self._record_expression(first_generator.iter, state)
        comprehension_state = state.clone()
        self._invalidate_target(first_generator.target, comprehension_state)
        for condition in first_generator.ifs:
            self._record_expression(condition, comprehension_state)
        # Later iterables can use earlier targets and bind their own fresh values in order.
        for generator in remaining_generators:
            self._record_expression(generator.iter, comprehension_state)
            self._invalidate_target(generator.target, comprehension_state)
            for condition in generator.ifs:
                self._record_expression(condition, comprehension_state)
        if isinstance(expression, ast.DictComp):
            self._record_expression(expression.key, comprehension_state)
            self._record_expression(expression.value, comprehension_state)
            return
        self._record_expression(expression.elt, comprehension_state)

    def _assign_target(
        self,
        assignment_target: ast.expr,
        assigned_expression: ast.expr,
        state: _FlowState,
    ) -> None:
        """Propagate a direct safe result or invalidate names receiving uncertain data.

        Args:
            assignment_target: User name or unpacking shape receiving the value.
            assigned_expression: Right-hand value evaluated under the current state.
            state: Proof state mutated for following statements.
        """
        # A direct name can preserve a sanitizer proof or one readable alias hop.
        if isinstance(assignment_target, ast.Name):
            self._assign_name(assignment_target.id, assigned_expression, state)
            return
        # Unpacking does not prove which runtime element reaches each displayed name.
        if isinstance(assignment_target, (ast.Tuple, ast.List)):
            # Every unpacked target loses prior safety independently.
            for unpacked_target in assignment_target.elts:
                self._invalidate_target(unpacked_target, state)
            return
        self._invalidate_target(assignment_target, state)

    def _assign_name(
        self,
        assigned_name: str,
        assigned_expression: ast.expr,
        state: _FlowState,
    ) -> None:
        """Update both slot proofs for one user variable and shadow callable trust.

        Args:
            assigned_name: Local name visible to later rendered links.
            assigned_expression: Value the user assigned at this source position.
            state: Proof state mutated for subsequent expressions.
        """
        # Label and URL proofs remain separate even when assigned to the same name.
        for slot_name in _MARKDOWN_SLOTS:
            proof = self._expression_safety(assigned_expression, slot_name, state)
            tracked_values = state.values_for(slot_name)
            previous_value = tracked_values.get(assigned_name)
            # A safe name-to-name assignment consumes the single supported alias hop.
            if proof.is_safe:
                alias_hops = proof.alias_hops + int(isinstance(assigned_expression, ast.Name))
                # A second alias is outside the bounded user explanation and loses trust.
                if alias_hops > 1:
                    tracked_values[assigned_name] = _TrackedValue(is_safe=False)
                else:
                    tracked_values[assigned_name] = _TrackedValue(
                        is_safe=True,
                        alias_hops=alias_hops,
                    )
                continue
            # An overwrite or uncertain branch preserves the user's warning reason.
            if (
                previous_value is not None and previous_value.is_safe
            ) or proof.sanitizer_resolution == "uncertain-provenance":
                tracked_values[assigned_name] = _TrackedValue(is_safe=False)
            else:
                tracked_values.pop(assigned_name, None)
        state.callables.shadow(assigned_name)

    def _invalidate_target(self, target: ast.expr, state: _FlowState) -> None:
        """Remove value/callable trust for every user name bound by a target.

        Args:
            target: Assignment, loop, with, or deletion target from user code.
            state: Proof state mutated for later rendered links.
        """
        user_bound_names = bound_names(target)
        # Each bound name may replace a previously sanitized display or click value.
        for bound_name in user_bound_names:
            self._invalidate_name(bound_name, state)
        target_root = target_root_name(target)
        # Attribute mutation such as `urllib.parse.quote = identity` shadows its root.
        if target_root is not None:
            state.callables.shadow(target_root)

    def _invalidate_name(self, bound_name: str, state: _FlowState) -> None:
        """Mark one bound name uncertain after user code replaces its prior value.

        Args:
            bound_name: Local identifier; empty text means no Python name was bound.
            state: Proof state mutated for subsequent rendered links.
        """
        # Each slot remembers an overwrite only when a safe value existed before it.
        for tracked_values in (state.label_values, state.url_values):
            previous_value = tracked_values.get(bound_name)
            # A safe display/click value becoming unknown must remain visibly uncertain.
            if previous_value is not None and previous_value.is_safe:
                tracked_values[bound_name] = _TrackedValue(is_safe=False)
            else:
                tracked_values.pop(bound_name, None)
        state.callables.shadow(bound_name)

    def _apply_import(self, imported_alias: ast.alias, state: _FlowState) -> None:
        """Map one `import` spelling to its canonical same-file binding.

        Args:
            imported_alias: Parsed import name and optional alias from user code.
            state: Proof state mutated for later calls.
        """
        # `import package.module as local` binds the alias to the complete module.
        if imported_alias.asname is not None:
            lexical_root = imported_alias.asname
            canonical_root = imported_alias.name
        else:
            # Plain `import urllib.parse` binds only the top-level `urllib` name.
            lexical_root = imported_alias.name.split(".", 1)[0]
            canonical_root = lexical_root
        self._invalidate_name(lexical_root, state)
        state.callables.bind_import(lexical_root, canonical_root)

    def _apply_from_import(self, statement: ast.ImportFrom, state: _FlowState) -> None:
        """Map exact from-import aliases without resolving another module's contents.

        Args:
            statement: User import whose module may be ``None`` for a relative form.
            state: Proof state mutated for later calls.
        """
        # Relative or missing modules cannot match an absolute configured target safely.
        if statement.module is None or statement.level:
            # Every visible alias is still a runtime binding that can shadow exact trust.
            for imported_alias in statement.names:
                # Wildcard imports expose no bounded lexical name to track.
                if imported_alias.name == "*":
                    continue
                lexical_root = imported_alias.asname or imported_alias.name
                self._invalidate_name(lexical_root, state)
            return
        # Each explicit imported name maps directly to its canonical callable target.
        for imported_alias in statement.names:
            # Wildcard imports cannot prove which call target the user receives.
            if imported_alias.name == "*":
                continue
            lexical_root = imported_alias.asname or imported_alias.name
            canonical_root = f"{statement.module}.{imported_alias.name}"
            self._invalidate_name(lexical_root, state)
            state.callables.bind_import(lexical_root, canonical_root)

    def _bind_declaration_name(
        self,
        declared_name: str,
        state: _FlowState,
        scope_kind: Literal["module", "class", "function"],
    ) -> None:
        """Bind a function/class name without distrusting an exact module helper declaration.

        Args:
            declared_name: Function or class identifier visible after the declaration.
            state: Outer proof state mutated for following statements.
            scope_kind: Module declarations may be the configured helper itself.
        """
        self._invalidate_name(declared_name, state)
        # A module helper configured by its exact bare name is an intentional trust boundary.
        if scope_kind == "module" and (
            declared_name in self._label_targets or declared_name in self._url_targets
        ):
            state.callables.shadowed_roots.discard(declared_name)

    def _expression_safety(
        self,
        expression: ast.expr,
        slot: MarkdownSlot,
        state: _FlowState,
    ) -> ExpressionSafety:
        """Prove one expression from literals, configured calls, or bounded local state.

        Args:
            expression: User value eventually rendered into a Markdown link.
            slot: Label or URL proof requested by the sink.
            state: Statement-ordered snapshot at the expression's source position.

        Returns:
            Safe proof or a stable user-facing reason for the finding.
        """
        # Literal values cannot carry runtime user input into link delimiters.
        if isinstance(expression, ast.Constant):
            return _safe()
        # A local name is safe only when its current slot-specific assignment proved it.
        if isinstance(expression, ast.Name):
            tracked_value = state.values_for(slot).get(expression.id)
            # Missing names are raw parameters, globals, or closure values from the user's view.
            if tracked_value is None:
                return _unsafe("raw")
            # An overwrite or branch disagreement remains unsafe at the final rendering site.
            if not tracked_value.is_safe:
                return _unsafe("uncertain-provenance")
            return _safe(alias_hops=tracked_value.alias_hops)
        # Calls require an exact configured target and any default-quote argument proof.
        if isinstance(expression, ast.Call):
            return self._call_safety(expression, slot, state.callables)
        # Conditional values are safe only when both runtime outcomes are safe.
        if isinstance(expression, ast.IfExp):
            return combine_expression_safety(
                [
                    self._expression_safety(expression.body, slot, state),
                    self._expression_safety(expression.orelse, slot, state),
                ]
            )
        # Boolean expressions may return any operand, so every operand must be safe.
        if isinstance(expression, ast.BoolOp):
            return combine_expression_safety(
                [self._expression_safety(value, slot, state) for value in expression.values]
            )
        # Concatenation/composition is safe only when both possible value sources are safe.
        if isinstance(expression, ast.BinOp):
            return combine_composed_safety(
                [
                    self._expression_safety(expression.left, slot, state),
                    self._expression_safety(expression.right, slot, state),
                ]
            )
        # Nested f-strings are safe only when every formatted value is already safe.
        if isinstance(expression, ast.JoinedStr):
            formatted_values = [
                value.value for value in expression.values if isinstance(value, ast.FormattedValue)
            ]
            # A static-only nested f-string is equivalent to a literal.
            if not formatted_values:
                return _safe()
            return combine_expression_safety(
                [self._expression_safety(value, slot, state) for value in formatted_values]
            )
        # FormattedValue appears only as an f-string wrapper around its real expression.
        if isinstance(expression, ast.FormattedValue):
            return self._expression_safety(expression.value, slot, state)
        return _unsafe("raw")

    def _call_safety(
        self,
        call: ast.Call,
        slot: MarkdownSlot,
        callables: _CallableBindings,
    ) -> ExpressionSafety:
        """Match one call against exact slot targets and binding/argument controls.

        Args:
            call: User call wrapping the interpolated value.
            slot: Label or URL slot that needs a sanitizer proof.
            callables: Same-position import aliases and shadowed roots.

        Returns:
            Safe proof or the precise reason the call remains a finding.
        """
        lexical_target = call_target_name(call)
        # Lambdas and other dynamic callees have no exact user-configurable spelling.
        if lexical_target is None:
            return _unsafe("unconfigured-call")
        resolved_target = callables.resolved_target(lexical_target)
        canonical_target = resolved_target.canonical_target
        # A user assignment or parameter can replace an otherwise configured helper.
        if resolved_target.is_shadowed or canonical_target is None:
            return _unsafe("shadowed-target")
        requested_targets = self._label_targets if slot == "label" else self._url_targets
        other_targets = self._url_targets if slot == "label" else self._label_targets
        target_spellings = {lexical_target, canonical_target}
        # The current slot trusts either the exact spelling or its proven import canonicalization.
        if target_spellings & requested_targets:
            # A splat or delimiter-preserving `safe` defeats Python's default quote
            # helpers. This applies to both slots: `]`, `(`, and `)` break out of a
            # visible label exactly as they break out of a click target.
            if canonical_target in _DEFAULT_QUOTE_TARGETS and not is_quote_call_delimiter_safe(
                call
            ):
                return _unsafe("unsafe-arguments")
            return _safe()
        # A helper configured for the other slot gives users a specific correction path.
        if target_spellings & other_targets:
            return _unsafe("wrong-slot")
        return _unsafe("unconfigured-call")
