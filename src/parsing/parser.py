"""
Tree-sitter Python parser wrapper
"""

import os
from pathlib import Path
from typing import List, Optional, Dict, Any
import tree_sitter_python as tspython
from tree_sitter import Language, Parser, Node

from .ast_utils import ASTNode, CallExpression, FunctionDef, ImportStatement


class PythonParser:
    """Tree-sitter parser for Python code with caching and utilities"""

    def __init__(self):
        self.language = Language(tspython.language())
        self.parser = Parser(self.language)
        self._ast_cache: Dict[str, ASTNode] = {}

    def parse_file(self, file_path: str) -> Optional[ASTNode]:
        """Parse a Python file and return the root AST node"""
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            # Check cache first
            mtime = path.stat().st_mtime
            cache_key = f"{file_path}:{mtime}"
            if cache_key in self._ast_cache:
                return self._ast_cache[cache_key]

            # Read and parse file
            with open(file_path, 'rb') as f:
                source_code = f.read()

            tree = self.parser.parse(source_code)
            if not tree.root_node:
                return None

            ast_node = ASTNode(tree.root_node, source_code)
            self._ast_cache[cache_key] = ast_node
            return ast_node

        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None

    def parse_string(self, code: str) -> Optional[ASTNode]:
        """Parse Python code from a string"""
        try:
            source_code = code.encode('utf-8')
            tree = self.parser.parse(source_code)
            if not tree.root_node:
                return None
            return ASTNode(tree.root_node, source_code)
        except Exception as e:
            print(f"Error parsing code string: {e}")
            return None

    def get_functions(self, ast: ASTNode) -> List[FunctionDef]:
        """Extract all function definitions from the AST"""
        functions = []
        function_nodes = ast.find_children_by_type('function_definition')

        for node in function_nodes:
            try:
                func_def = FunctionDef(node.node, ast.source_code)
                functions.append(func_def)
            except ValueError:
                continue

        return functions

    def get_calls(self, ast: ASTNode) -> List[CallExpression]:
        """Extract all function calls from the AST"""
        calls = []
        call_nodes = ast.find_children_by_type('call')

        for node in call_nodes:
            try:
                call_expr = CallExpression(node.node, ast.source_code)
                calls.append(call_expr)
            except ValueError:
                continue

        return calls

    def get_imports(self, ast: ASTNode) -> List[ImportStatement]:
        """Extract all import statements from the AST"""
        imports = []
        import_nodes = ast.find_children_by_type('import_statement')
        import_from_nodes = ast.find_children_by_type('import_from_statement')

        for node in import_nodes + import_from_nodes:
            try:
                import_stmt = ImportStatement(node.node, ast.source_code)
                imports.append(import_stmt)
            except ValueError:
                continue

        return imports

    def find_nodes_by_type(self, ast: ASTNode, node_type: str) -> List[ASTNode]:
        """Find all nodes of a specific type in the AST"""
        return ast.find_children_by_type(node_type)

    def get_node_at_position(self, ast: ASTNode, line: int, column: int) -> Optional[ASTNode]:
        """Find the AST node at a specific line/column position"""
        def search_node(node: ASTNode) -> Optional[ASTNode]:
            start_line, start_col = node.start_point
            end_line, end_col = node.end_point

            # Check if position is within this node
            if (start_line <= line <= end_line and
                (line > start_line or column >= start_col) and
                (line < end_line or column <= end_col)):

                # Try to find a more specific child node
                for child in node.children():
                    result = search_node(child)
                    if result:
                        return result

                # If no child matches, return this node
                return node

            return None

        return search_node(ast)

    def extract_code_snippet(self, ast: ASTNode, node: ASTNode, context_lines: int = 2) -> str:
        """Extract code snippet around a node with context"""
        source_lines = ast.source_code.decode('utf-8').splitlines()
        start_line = max(0, node.start_point[0] - context_lines)
        end_line = min(len(source_lines), node.end_point[0] + context_lines + 1)

        snippet_lines = source_lines[start_line:end_line]
        return '\n'.join(snippet_lines)

    def clear_cache(self) -> None:
        """Clear the AST cache"""
        self._ast_cache.clear()

    def get_syntax_errors(self, ast: ASTNode) -> List[Dict[str, Any]]:
        """Find syntax errors in the AST"""
        errors = []

        def find_errors(node: ASTNode) -> None:
            if node.node.is_error:
                errors.append({
                    'type': 'syntax_error',
                    'message': f"Syntax error at {node.start_point}",
                    'start_point': node.start_point,
                    'end_point': node.end_point,
                    'text': node.text
                })

            for child in node.children():
                find_errors(child)

        find_errors(ast)
        return errors

    def get_file_stats(self, ast: ASTNode) -> Dict[str, Any]:
        """Get basic statistics about the parsed file"""
        functions = self.get_functions(ast)
        calls = self.get_calls(ast)
        imports = self.get_imports(ast)

        source_lines = ast.source_code.decode('utf-8').splitlines()
        non_empty_lines = [line for line in source_lines if line.strip()]

        return {
            'total_lines': len(source_lines),
            'non_empty_lines': len(non_empty_lines),
            'function_count': len(functions),
            'call_count': len(calls),
            'import_count': len(imports),
            'file_size_bytes': len(ast.source_code)
        }