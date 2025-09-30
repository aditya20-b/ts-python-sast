"""
Call graph construction engine
"""

import re
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque

from ..parsing.ast_utils import ASTNode, CallExpression, FunctionDef
from ..parsing.parser import PythonParser
from .models import CallGraph, CallEdge, CallType, NodeType, SymbolInfo
from .symbol_table import SymbolTableBuilder


class CallGraphBuilder:
    """Builds call graphs from Python source code"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.parser = PythonParser()
        self.symbol_builder = SymbolTableBuilder(file_path)

    def build(self, ast: ASTNode) -> CallGraph:
        """Build complete call graph from AST"""
        # Build symbol table first
        symbols = self.symbol_builder.build(ast)

        # Find all function calls
        call_edges = self._build_call_edges(ast)

        # Identify entry points
        entry_points = self._identify_entry_points(ast, symbols)

        # Count external calls
        external_calls = self._count_external_calls(call_edges, symbols)

        # Find unresolved calls
        unresolved_calls = self._find_unresolved_calls(call_edges, symbols)

        # Create call graph
        call_graph = CallGraph(
            file_path=self.file_path,
            symbols=symbols,
            edges=call_edges,
            entry_points=entry_points,
            external_calls=external_calls,
            unresolved_calls=unresolved_calls,
            analysis_metadata=self._generate_metadata(symbols, call_edges)
        )

        return call_graph

    def _build_call_edges(self, ast: ASTNode) -> List[CallEdge]:
        """Extract all function call edges from AST"""
        edges = []
        current_function = None

        def visit_node(node: ASTNode, function_context: Optional[str] = None) -> None:
            nonlocal current_function

            # Track current function context
            if node.type == 'function_definition':
                try:
                    func_def = FunctionDef(node.node, node.source_code)
                    old_function = current_function
                    current_function = self.symbol_builder.current_scope.get_qualified_name(func_def.name)

                    # Process function body
                    if func_def.body:
                        visit_node(func_def.body, current_function)

                    current_function = old_function
                    return
                except ValueError:
                    pass

            # Process function calls
            elif node.type == 'call' and current_function:
                try:
                    call_expr = CallExpression(node.node, node.source_code)
                    edge = self._create_call_edge(call_expr, current_function)
                    if edge:
                        edges.append(edge)
                except ValueError:
                    pass

            # Recursively visit children
            for child in node.children():
                visit_node(child, current_function)

        visit_node(ast)
        return edges

    def _create_call_edge(self, call_expr: CallExpression, caller: str) -> Optional[CallEdge]:
        """Create call edge from function call expression"""
        # Resolve call target
        callee = self.symbol_builder.resolve_call_target(call_expr)
        if not callee:
            return None

        # Determine call type
        call_type = self._determine_call_type(call_expr, caller, callee)

        # Check if call is conditional (simple heuristic)
        is_conditional = self._is_conditional_call(call_expr)

        # Determine confidence
        confidence = self._calculate_call_confidence(call_expr, callee)

        return CallEdge(
            caller=caller,
            callee=callee,
            call_type=call_type,
            file_path=self.file_path,
            line=call_expr.start_point[0] + 1,
            column=call_expr.start_point[1] + 1,
            call_expression=call_expr.text,
            is_conditional=is_conditional,
            confidence=confidence
        )

    def _determine_call_type(self, call_expr: CallExpression, caller: str, callee: str) -> CallType:
        """Determine the type of function call"""
        # Self-recursive call
        if caller == callee:
            return CallType.RECURSIVE

        # Direct function call (most common)
        func_name = call_expr.function_name
        if func_name and not '.' in call_expr.qualified_name:
            return CallType.DIRECT

        # Indirect call through variable or attribute
        if '.' in call_expr.qualified_name or call_expr.qualified_name != func_name:
            # Check if it's a resolved assignment
            resolved = self.symbol_builder.current_scope.resolve_name(func_name)
            if resolved and resolved != func_name:
                return CallType.INDIRECT

        # Default to direct for now
        return CallType.DIRECT

    def _is_conditional_call(self, call_expr: CallExpression) -> bool:
        """Check if function call is inside conditional statement"""
        # This is a simplified heuristic - could be improved with proper AST traversal
        call_text = call_expr.text
        parent_context = ""  # Would need AST parent traversal for proper implementation

        # Simple pattern matching for common conditionals
        conditional_patterns = [
            r'\bif\b.*' + re.escape(call_text[:20]),
            r'\belif\b.*' + re.escape(call_text[:20]),
            r'\band\b.*' + re.escape(call_text[:20]),
            r'\bor\b.*' + re.escape(call_text[:20])
        ]

        for pattern in conditional_patterns:
            if re.search(pattern, parent_context, re.IGNORECASE):
                return True

        return False

    def _calculate_call_confidence(self, call_expr: CallExpression, callee: str) -> float:
        """Calculate confidence in call resolution"""
        # High confidence for direct calls to known functions
        if callee in self.symbol_builder.symbols:
            return 1.0

        # Medium confidence for builtin functions
        if callee.startswith('<builtin>'):
            return 0.9

        # Lower confidence for external/unresolved calls
        if '.' in callee:
            return 0.7

        # Very low confidence for unresolved calls
        return 0.3

    def _identify_entry_points(self, ast: ASTNode, symbols: Dict[str, SymbolInfo]) -> Set[str]:
        """Identify entry point functions"""
        entry_points = set()

        # Look for if __name__ == "__main__": pattern
        main_block_functions = self._find_main_block_calls(ast)
        entry_points.update(main_block_functions)

        # Top-level function calls (not inside other functions)
        top_level_calls = self._find_top_level_calls(ast)
        entry_points.update(top_level_calls)

        # Functions with specific names that are likely entry points
        for qualified_name, symbol in symbols.items():
            if symbol.name in ('main', 'run', 'start', 'execute', 'handler'):
                entry_points.add(qualified_name)

        # Functions with decorators that indicate entry points
        for qualified_name, symbol in symbols.items():
            if any(decorator in symbol.decorators for decorator in ['app.route', 'click.command', 'task']):
                entry_points.add(qualified_name)

        return entry_points

    def _find_main_block_calls(self, ast: ASTNode) -> Set[str]:
        """Find function calls inside if __name__ == "__main__": blocks"""
        main_calls = set()

        def visit_node(node: ASTNode, in_main_block: bool = False) -> None:
            # Look for if statements with __name__ == "__main__" condition
            if node.type == 'if_statement' and not in_main_block:
                condition = node.child_by_field_name('condition')
                if condition and '__name__' in condition.text and '__main__' in condition.text:
                    # Process the if body
                    body = node.child_by_field_name('consequence')
                    if body:
                        visit_node(body, True)
                    return

            # If we're in main block, collect function calls
            if in_main_block and node.type == 'call':
                try:
                    call_expr = CallExpression(node.node, node.source_code)
                    callee = self.symbol_builder.resolve_call_target(call_expr)
                    if callee and callee in self.symbol_builder.symbols:
                        main_calls.add(callee)
                except ValueError:
                    pass

            # Continue traversing
            for child in node.children():
                visit_node(child, in_main_block)

        visit_node(ast)
        return main_calls

    def _find_top_level_calls(self, ast: ASTNode) -> Set[str]:
        """Find function calls at module level (not inside functions)"""
        top_level_calls = set()

        def visit_node(node: ASTNode, depth: int = 0, in_function: bool = False) -> None:
            # Track if we're inside a function
            if node.type == 'function_definition':
                # Process function body but mark as inside function
                body = node.child_by_field_name('body')
                if body:
                    for child in body.children():
                        visit_node(child, depth + 1, True)
                return

            # If we're at top level (not in function), collect calls
            if not in_function and node.type == 'call':
                try:
                    call_expr = CallExpression(node.node, node.source_code)
                    callee = self.symbol_builder.resolve_call_target(call_expr)
                    if callee and callee in self.symbol_builder.symbols:
                        top_level_calls.add(callee)
                except ValueError:
                    pass

            # Continue traversing
            for child in node.children():
                visit_node(child, depth, in_function)

        visit_node(ast)
        return top_level_calls

    def _count_external_calls(self, edges: List[CallEdge], symbols: Dict[str, SymbolInfo]) -> Dict[str, int]:
        """Count calls to external functions"""
        external_calls = defaultdict(int)

        for edge in edges:
            # If callee is not in our symbol table, it's external
            if edge.callee not in symbols:
                external_calls[edge.callee] += 1

        return dict(external_calls)

    def _find_unresolved_calls(self, edges: List[CallEdge], symbols: Dict[str, SymbolInfo]) -> List[str]:
        """Find calls that couldn't be resolved"""
        unresolved = []

        for edge in edges:
            # Low confidence calls or calls to unknown functions
            if edge.confidence < 0.5 or (
                edge.callee not in symbols and
                not edge.callee.startswith('<builtin>') and
                not '.' in edge.callee
            ):
                unresolved.append(edge.call_expression)

        return unresolved

    def _generate_metadata(self, symbols: Dict[str, SymbolInfo], edges: List[CallEdge]) -> Dict[str, Any]:
        """Generate analysis metadata"""
        return {
            'total_functions': len(symbols),
            'total_calls': len(edges),
            'avg_calls_per_function': len(edges) / max(len(symbols), 1),
            'function_types': {
                node_type.value: sum(1 for s in symbols.values() if s.node_type == node_type)
                for node_type in NodeType
            },
            'call_types': {
                call_type.value: sum(1 for e in edges if e.call_type == call_type)
                for call_type in CallType
            },
            'complexity_stats': {
                'avg_complexity': sum(s.complexity for s in symbols.values()) / max(len(symbols), 1),
                'max_complexity': max((s.complexity for s in symbols.values()), default=0),
                'high_complexity_functions': [
                    s.qualified_name for s in symbols.values() if s.complexity > 10
                ]
            },
            'scope_info': self.symbol_builder.get_scope_info()
        }