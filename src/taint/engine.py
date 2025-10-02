"""
Dataflow engine for taint analysis
"""

from typing import Dict, Set, List, Optional, Tuple
from collections import defaultdict
from ..parsing.ast_utils import ASTNode, CallExpression
from .models import (
    TaintedValue, TaintStatus, TaintLabel, TaintFlowEdge,
    TaintPath, SourceType, SinkType, TaintAnalysisResult
)
from .sources import SourceConfig
from .sinks import SinkConfig
from .sanitizers import SanitizerConfig
import time


class TaintState:
    """Represents taint state at a program point"""

    def __init__(self):
        self.tainted_vars: Dict[str, TaintedValue] = {}

    def mark_tainted(
        self,
        var_name: str,
        labels: Set[TaintLabel],
        source_location: str,
        source_line: int
    ) -> None:
        """Mark a variable as tainted"""
        self.tainted_vars[var_name] = TaintedValue(
            variable_name=var_name,
            taint_status=TaintStatus.TAINTED,
            taint_labels=labels,
            source_location=source_location,
            source_line=source_line
        )

    def mark_sanitized(self, var_name: str, removed_labels: List[TaintLabel]) -> None:
        """Mark a variable as sanitized (remove specific labels)"""
        if var_name in self.tainted_vars:
            tainted_val = self.tainted_vars[var_name]
            remaining_labels = tainted_val.taint_labels - set(removed_labels)

            if not remaining_labels:
                # All labels removed - mark as sanitized
                tainted_val.taint_status = TaintStatus.SANITIZED
                tainted_val.taint_labels = set()
            else:
                # Some labels remain
                tainted_val.taint_labels = remaining_labels

    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted"""
        if var_name not in self.tainted_vars:
            return False
        tainted_val = self.tainted_vars[var_name]
        return tainted_val.taint_status == TaintStatus.TAINTED and len(tainted_val.taint_labels) > 0

    def get_taint_labels(self, var_name: str) -> Set[TaintLabel]:
        """Get taint labels for a variable"""
        if var_name in self.tainted_vars:
            return self.tainted_vars[var_name].taint_labels
        return set()

    def get_tainted_value(self, var_name: str) -> Optional[TaintedValue]:
        """Get full tainted value info"""
        return self.tainted_vars.get(var_name)

    def propagate_taint(
        self,
        from_var: str,
        to_var: str
    ) -> None:
        """Propagate taint from one variable to another"""
        if from_var in self.tainted_vars:
            source_val = self.tainted_vars[from_var]
            self.tainted_vars[to_var] = TaintedValue(
                variable_name=to_var,
                taint_status=source_val.taint_status,
                taint_labels=source_val.taint_labels.copy(),
                source_location=source_val.source_location,
                source_line=source_val.source_line
            )

    def merge_taint(self, from_vars: List[str], to_var: str) -> None:
        """Merge taint from multiple variables"""
        all_labels = set()
        source_location = None
        source_line = None

        for var in from_vars:
            if var in self.tainted_vars:
                tainted_val = self.tainted_vars[var]
                if tainted_val.taint_status == TaintStatus.TAINTED:
                    all_labels.update(tainted_val.taint_labels)
                    if not source_location:
                        source_location = tainted_val.source_location
                        source_line = tainted_val.source_line

        if all_labels:
            self.tainted_vars[to_var] = TaintedValue(
                variable_name=to_var,
                taint_status=TaintStatus.TAINTED,
                taint_labels=all_labels,
                source_location=source_location,
                source_line=source_line
            )

    def copy(self) -> 'TaintState':
        """Create a copy of this state"""
        new_state = TaintState()
        for var_name, tainted_val in self.tainted_vars.items():
            new_state.tainted_vars[var_name] = TaintedValue(
                variable_name=tainted_val.variable_name,
                taint_status=tainted_val.taint_status,
                taint_labels=tainted_val.taint_labels.copy(),
                source_location=tainted_val.source_location,
                source_line=tainted_val.source_line
            )
        return new_state


class DataflowEngine:
    """Engine for intra-procedural taint tracking"""

    def __init__(
        self,
        source_config: SourceConfig,
        sink_config: SinkConfig,
        sanitizer_config: SanitizerConfig
    ):
        self.source_config = source_config
        self.sink_config = sink_config
        self.sanitizer_config = sanitizer_config

        # Track flows and paths
        self.flow_edges: List[TaintFlowEdge] = []
        self.taint_paths: List[TaintPath] = []

    def analyze_function(
        self,
        func_node: ASTNode,
        file_path: str
    ) -> Tuple[List[TaintFlowEdge], List[TaintPath]]:
        """Analyze a function for taint flows"""
        self.flow_edges = []
        self.taint_paths = []

        # Get function body
        body = func_node.child_by_field_name('body')
        if not body:
            return self.flow_edges, self.taint_paths

        # Initialize taint state
        state = TaintState()

        # Analyze statements in function body
        self._analyze_statements(body, state, file_path)

        return self.flow_edges, self.taint_paths

    def _analyze_statements(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze a sequence of statements"""
        for child in node.children():
            if child.type in ['expression_statement', 'assignment', 'augmented_assignment']:
                self._analyze_statement(child, state, file_path)
            elif child.type == 'if_statement':
                self._analyze_if_statement(child, state, file_path)
            elif child.type in ['for_statement', 'while_statement']:
                self._analyze_loop(child, state, file_path)
            elif child.type == 'with_statement':
                self._analyze_with_statement(child, state, file_path)
            elif child.type == 'return_statement':
                self._analyze_return(child, state, file_path)

    def _analyze_statement(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze a single statement"""
        # Handle assignments
        if node.type == 'assignment':
            self._analyze_assignment(node, state, file_path)
        elif node.type == 'augmented_assignment':
            self._analyze_augmented_assignment(node, state, file_path)
        elif node.type == 'expression_statement':
            # Get the actual expression
            expr = node.child_by_field_name('expression')
            if not expr and node.children():
                expr = node.children()[0]

            if expr:
                # Check if it's an assignment inside expression_statement
                if expr.type == 'assignment':
                    self._analyze_assignment(expr, state, file_path)
                elif expr.type == 'augmented_assignment':
                    self._analyze_augmented_assignment(expr, state, file_path)
                elif expr.type == 'call':
                    self._check_sink_call(expr, state, file_path)

    def _analyze_assignment(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze assignment statement"""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')

        if not left or not right:
            return

        # Get variable name being assigned
        var_name = self._extract_var_name(left)
        if not var_name:
            return

        # Check if right side is a taint source
        if right.type == 'call':
            self._check_source_call(right, var_name, state, file_path)
            self._check_sanitizer_call(right, var_name, state, file_path)
            self._check_sink_call(right, state, file_path)

        # Check if right side is a tainted variable
        tainted_vars = self._find_tainted_vars_in_expr(right, state)
        if tainted_vars:
            # Propagate taint
            state.merge_taint(tainted_vars, var_name)

            # Record flow edge
            for tainted_var in tainted_vars:
                self.flow_edges.append(TaintFlowEdge(
                    from_var=tainted_var,
                    to_var=var_name,
                    operation='assignment',
                    location=file_path,
                    line=node.start_point[0] + 1,
                    preserves_taint=True
                ))

    def _analyze_augmented_assignment(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze augmented assignment (+=, etc.)"""
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')

        if not left or not right:
            return

        var_name = self._extract_var_name(left)
        if not var_name:
            return

        # Augmented assignment merges old and new values
        tainted_vars = self._find_tainted_vars_in_expr(right, state)
        if var_name in state.tainted_vars:
            tainted_vars.append(var_name)

        if tainted_vars:
            state.merge_taint(tainted_vars, var_name)

    def _analyze_if_statement(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze if statement (simplified - no path sensitivity)"""
        # Analyze consequence
        consequence = node.child_by_field_name('consequence')
        if consequence:
            self._analyze_statements(consequence, state, file_path)

        # Analyze alternative
        alternative = node.child_by_field_name('alternative')
        if alternative:
            if alternative.type == 'else_clause':
                body = alternative.child_by_field_name('body')
                if body:
                    self._analyze_statements(body, state, file_path)
            elif alternative.type == 'elif_clause':
                self._analyze_if_statement(alternative, state, file_path)

    def _analyze_loop(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze loop statement"""
        body = node.child_by_field_name('body')
        if body:
            # Simplified: single pass (no fixpoint iteration)
            self._analyze_statements(body, state, file_path)

    def _analyze_with_statement(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze with statement"""
        body = node.child_by_field_name('body')
        if body:
            self._analyze_statements(body, state, file_path)

    def _analyze_return(
        self,
        node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Analyze return statement"""
        # Check if returning tainted data
        return_value = node.children()
        if len(return_value) > 1:
            expr = return_value[1]
            tainted_vars = self._find_tainted_vars_in_expr(expr, state)
            if tainted_vars:
                # Record flow to return
                for var in tainted_vars:
                    self.flow_edges.append(TaintFlowEdge(
                        from_var=var,
                        to_var='<return>',
                        operation='return',
                        location=file_path,
                        line=node.start_point[0] + 1,
                        preserves_taint=True
                    ))

    def _check_source_call(
        self,
        call_node: ASTNode,
        var_name: str,
        state: TaintState,
        file_path: str
    ) -> None:
        """Check if call is a taint source"""
        try:
            call_expr = CallExpression(call_node.node, call_node.source_code)
            source = self.source_config.is_source(call_expr)

            if source:
                # Mark variable as tainted
                location = f"{file_path}:{call_node.start_point[0] + 1}"
                state.mark_tainted(
                    var_name,
                    {source.taint_label},
                    location,
                    call_node.start_point[0] + 1
                )

                # Record flow edge
                self.flow_edges.append(TaintFlowEdge(
                    from_var=source.name,
                    to_var=var_name,
                    operation='source',
                    location=file_path,
                    line=call_node.start_point[0] + 1,
                    preserves_taint=True
                ))
        except ValueError:
            pass

    def _check_sanitizer_call(
        self,
        call_node: ASTNode,
        var_name: str,
        state: TaintState,
        file_path: str
    ) -> None:
        """Check if call is a sanitizer"""
        try:
            call_expr = CallExpression(call_node.node, call_node.source_code)
            sanitizer = self.sanitizer_config.is_sanitizer(call_expr)

            if sanitizer:
                # Check if sanitizing tainted data
                args = call_expr.arguments
                if args:
                    for arg in args:
                        tainted_vars = self._find_tainted_vars_in_expr(arg, state)
                        if tainted_vars:
                            # Mark as sanitized
                            state.mark_sanitized(var_name, sanitizer.removes_labels)

                            # Record flow edge with sanitizer
                            for tainted_var in tainted_vars:
                                self.flow_edges.append(TaintFlowEdge(
                                    from_var=tainted_var,
                                    to_var=var_name,
                                    operation='sanitize',
                                    location=file_path,
                                    line=call_node.start_point[0] + 1,
                                    preserves_taint=False,
                                    sanitizer_applied=sanitizer.name
                                ))
        except ValueError:
            pass

    def _check_sink_call(
        self,
        call_node: ASTNode,
        state: TaintState,
        file_path: str
    ) -> None:
        """Check if call is a sink with tainted arguments"""
        try:
            call_expr = CallExpression(call_node.node, call_node.source_code)
            sink = self.sink_config.is_sink(call_expr)

            if sink:
                # Check if any vulnerable arguments are tainted
                args = call_expr.arguments
                for arg_idx, arg in enumerate(args):
                    if sink.vulnerable_params and arg_idx not in sink.vulnerable_params:
                        continue

                    tainted_vars = self._find_tainted_vars_in_expr(arg, state)
                    if tainted_vars:
                        # Found taint path: source -> sink
                        for tainted_var in tainted_vars:
                            tainted_val = state.get_tainted_value(tainted_var)
                            if tainted_val:
                                self._create_taint_path(
                                    tainted_var,
                                    tainted_val,
                                    sink,
                                    call_node,
                                    file_path,
                                    state
                                )
        except ValueError:
            pass

    def _create_taint_path(
        self,
        source_var: str,
        tainted_val: TaintedValue,
        sink,
        sink_node: ASTNode,
        file_path: str,
        state: TaintState
    ) -> None:
        """Create a taint path from source to sink"""
        # Build path edges by tracing back through flow edges
        path_edges = []
        for edge in self.flow_edges:
            if edge.to_var == source_var or edge.from_var == source_var:
                path_edges.append(edge)

        # Check if path is sanitized
        sanitizers = [e.sanitizer_applied for e in path_edges if e.sanitizer_applied]
        is_sanitized = any(
            not e.preserves_taint for e in path_edges
        )

        # Determine if sanitization is effective
        if sanitizers and not is_sanitized:
            # Check if sanitizers remove the taint labels
            for sanitizer_name in sanitizers:
                removed_labels = self.sanitizer_config.get_removed_labels(sanitizer_name)
                if tainted_val.taint_labels.intersection(removed_labels):
                    is_sanitized = True
                    break

        # Create taint path
        taint_path = TaintPath(
            source=source_var,
            source_type=SourceType.USER_INPUT,  # Simplified
            source_location=tainted_val.source_location or file_path,
            source_line=tainted_val.source_line or 0,
            sink=sink.name,
            sink_type=sink.sink_type,
            sink_location=file_path,
            sink_line=sink_node.start_point[0] + 1,
            taint_labels=tainted_val.taint_labels,
            path_edges=path_edges,
            is_sanitized=is_sanitized,
            sanitizers=sanitizers,
            severity=sink.severity,
            confidence=0.8  # Simplified confidence
        )

        self.taint_paths.append(taint_path)

    def _find_tainted_vars_in_expr(
        self,
        node: ASTNode,
        state: TaintState
    ) -> List[str]:
        """Find all tainted variables in an expression"""
        tainted_vars = []

        def visit(n: ASTNode):
            if n.type == 'identifier':
                var_name = n.text
                if state.is_tainted(var_name):
                    tainted_vars.append(var_name)

            # Recursively visit children
            for child in n.children():
                visit(child)

        visit(node)
        return tainted_vars

    def _extract_var_name(self, node: ASTNode) -> Optional[str]:
        """Extract variable name from node"""
        if node.type == 'identifier':
            return node.text
        elif node.type == 'attribute':
            # For simplicity, use full attribute path
            return node.text
        elif node.type == 'subscript':
            # For x[0], use x
            value = node.child_by_field_name('value')
            if value:
                return self._extract_var_name(value)
        return None


class TaintAnalyzer:
    """Main taint analysis orchestrator"""

    def __init__(self):
        self.source_config = SourceConfig()
        self.sink_config = SinkConfig()
        self.sanitizer_config = SanitizerConfig()
        self.engine = DataflowEngine(
            self.source_config,
            self.sink_config,
            self.sanitizer_config
        )

    def analyze_file(self, file_path: str, ast_root: ASTNode) -> TaintAnalysisResult:
        """Analyze a file for taint vulnerabilities"""
        start_time = time.time()

        all_flow_edges = []
        all_taint_paths = []

        sources_found = 0
        sinks_found = 0
        sanitizers_found = 0

        # Detect sources, sinks, sanitizers
        sources_found = len(self.source_config.detect_sources_in_node(ast_root))
        sinks_found = len(self.sink_config.detect_sinks_in_node(ast_root))
        sanitizers_found = len(self.sanitizer_config.detect_sanitizers_in_node(ast_root))

        # Find all function definitions
        functions = self._find_functions(ast_root)

        # Analyze each function
        for func_node in functions:
            flow_edges, taint_paths = self.engine.analyze_function(func_node, file_path)
            all_flow_edges.extend(flow_edges)
            all_taint_paths.extend(taint_paths)

        # Calculate analysis time
        analysis_time_ms = (time.time() - start_time) * 1000

        return TaintAnalysisResult(
            file_path=file_path,
            taint_paths=all_taint_paths,
            sources_found=sources_found,
            sinks_found=sinks_found,
            sanitizers_found=sanitizers_found,
            analysis_time_ms=analysis_time_ms
        )

    def _find_functions(self, node: ASTNode) -> List[ASTNode]:
        """Find all function definitions in AST"""
        functions = []

        def visit(n: ASTNode):
            if n.type == 'function_definition':
                functions.append(n)

            for child in n.children():
                visit(child)

        visit(node)
        return functions
