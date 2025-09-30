"""
Symbol table builder for function and method discovery
"""

import re
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass

from ..parsing.ast_utils import ASTNode, FunctionDef, CallExpression, ImportStatement
from .models import SymbolInfo, NodeType


@dataclass
class Scope:
    """Represents a lexical scope in the code"""
    name: str
    level: int
    parent: Optional['Scope'] = None
    symbols: Dict[str, SymbolInfo] = None
    assignments: Dict[str, str] = None  # variable -> function mappings

    def __post_init__(self):
        if self.symbols is None:
            self.symbols = {}
        if self.assignments is None:
            self.assignments = {}

    def get_qualified_name(self, name: str) -> str:
        """Get fully qualified name within this scope"""
        if self.parent and self.name != "<module>":
            parent_qual = self.parent.get_qualified_name("")
            return f"{parent_qual}.{self.name}.{name}" if parent_qual else f"{self.name}.{name}"
        elif self.name != "<module>":
            return f"{self.name}.{name}"
        else:
            return name

    def resolve_name(self, name: str) -> Optional[str]:
        """Resolve a name to its qualified name, checking assignments"""
        # Check direct assignment in current scope
        if name in self.assignments:
            return self.assignments[name]

        # Check if it's a symbol in current scope
        if name in self.symbols:
            return self.symbols[name].qualified_name

        # Check parent scopes
        if self.parent:
            return self.parent.resolve_name(name)

        return None


class SymbolTableBuilder:
    """Builds symbol table for functions, methods, and their relationships"""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.symbols: Dict[str, SymbolInfo] = {}
        self.scopes: List[Scope] = []
        self.current_scope: Optional[Scope] = None
        self.imports: Dict[str, str] = {}  # alias -> module mappings
        self.module_imports: Set[str] = set()  # imported module names

    def build(self, ast: ASTNode) -> Dict[str, SymbolInfo]:
        """Build symbol table from AST"""
        # Initialize module scope
        self.current_scope = Scope("<module>", 0)
        self.scopes.append(self.current_scope)

        # Process imports first
        self._process_imports(ast)

        # Process all function definitions
        self._process_node(ast)

        return self.symbols

    def _process_imports(self, node: ASTNode) -> None:
        """Process import statements to track external symbols"""
        for child in node.children():
            if child.type in ('import_statement', 'import_from_statement'):
                try:
                    import_stmt = ImportStatement(child.node, child.source_code)
                    module = import_stmt.module_name
                    self.module_imports.add(module)

                    # Track imported names and their aliases
                    for name in import_stmt.imported_names:
                        if '.' in name or module:
                            qualified_name = f"{module}.{name}" if module else name
                            self.imports[name] = qualified_name
                except ValueError:
                    continue

            # Recursively process child nodes
            self._process_imports(child)

    def _process_node(self, node: ASTNode) -> None:
        """Process AST node for symbol information"""
        if node.type == 'function_definition':
            self._process_function(node)
        elif node.type == 'class_definition':
            self._process_class(node)
        elif node.type == 'assignment':
            self._process_assignment(node)

        # Recursively process children
        for child in node.children():
            self._process_node(child)

    def _process_function(self, node: ASTNode) -> None:
        """Process function definition"""
        try:
            func_def = FunctionDef(node.node, node.source_code)

            # Determine function type
            node_type = NodeType.METHOD if self._is_in_class() else NodeType.FUNCTION

            # Check for async/generator patterns
            is_async = 'async' in func_def.text[:20]  # Simple heuristic
            is_generator = 'yield' in func_def.text

            # Extract decorators
            decorators = self._extract_decorators(node)

            # Estimate complexity (simple heuristic)
            complexity = self._estimate_complexity(func_def.text)

            # Get qualified name
            qualified_name = self.current_scope.get_qualified_name(func_def.name)

            # Create symbol info
            symbol_info = SymbolInfo(
                name=func_def.name,
                qualified_name=qualified_name,
                node_type=node_type,
                file_path=self.file_path,
                start_line=func_def.start_point[0] + 1,
                start_column=func_def.start_point[1] + 1,
                end_line=func_def.end_point[0] + 1,
                end_column=func_def.end_point[1] + 1,
                parameters=[param.text for param in func_def.parameters],
                is_async=is_async,
                is_generator=is_generator,
                docstring=self._extract_docstring(func_def),
                decorators=decorators,
                complexity=complexity
            )

            # Add to symbol table
            self.symbols[qualified_name] = symbol_info
            self.current_scope.symbols[func_def.name] = symbol_info

            # Create new scope for function body
            func_scope = Scope(func_def.name, self.current_scope.level + 1, self.current_scope)
            self.scopes.append(func_scope)
            old_scope = self.current_scope
            self.current_scope = func_scope

            # Process function body
            if func_def.body:
                self._process_node(func_def.body)

            # Restore previous scope
            self.current_scope = old_scope

        except ValueError:
            pass

    def _process_class(self, node: ASTNode) -> None:
        """Process class definition"""
        name_node = node.child_by_field_name('name')
        if not name_node:
            return

        class_name = name_node.text
        qualified_name = self.current_scope.get_qualified_name(class_name)

        # Create class scope
        class_scope = Scope(class_name, self.current_scope.level + 1, self.current_scope)
        self.scopes.append(class_scope)
        old_scope = self.current_scope
        self.current_scope = class_scope

        # Process class body
        body = node.child_by_field_name('body')
        if body:
            self._process_node(body)

        # Restore previous scope
        self.current_scope = old_scope

    def _process_assignment(self, node: ASTNode) -> None:
        """Process assignment statements for function aliasing"""
        # Simple pattern: f = some_function
        left = node.child_by_field_name('left')
        right = node.child_by_field_name('right')

        if not left or not right:
            return

        # Handle simple identifier assignments
        if left.type == 'identifier' and right.type == 'identifier':
            var_name = left.text
            func_name = right.text

            # Resolve the right-hand side
            resolved = self.current_scope.resolve_name(func_name)
            if resolved:
                self.current_scope.assignments[var_name] = resolved

        # Handle attribute assignments (e.g., f = module.function)
        elif left.type == 'identifier' and right.type == 'attribute':
            var_name = left.text
            attr_qualified = self._resolve_attribute_name(right)
            if attr_qualified:
                self.current_scope.assignments[var_name] = attr_qualified

    def _resolve_attribute_name(self, attr_node: ASTNode) -> Optional[str]:
        """Resolve attribute access to qualified name"""
        obj = attr_node.child_by_field_name('object')
        attr = attr_node.child_by_field_name('attribute')

        if not obj or not attr:
            return None

        obj_name = obj.text
        attr_name = attr.text

        # Check if object is an imported module
        if obj_name in self.imports:
            return f"{self.imports[obj_name]}.{attr_name}"
        elif obj_name in self.module_imports:
            return f"{obj_name}.{attr_name}"

        # Try to resolve in current scope
        resolved_obj = self.current_scope.resolve_name(obj_name)
        if resolved_obj:
            return f"{resolved_obj}.{attr_name}"

        return f"{obj_name}.{attr_name}"

    def _extract_decorators(self, func_node: ASTNode) -> List[str]:
        """Extract decorator names from function definition"""
        decorators = []

        # Look for decorator nodes (simplified approach)
        for child in func_node.children():
            if child.type == 'decorator':
                decorator_name = child.text.strip('@')
                decorators.append(decorator_name)

        return decorators

    def _extract_docstring(self, func_def: FunctionDef) -> Optional[str]:
        """Extract docstring from function body"""
        body = func_def.body
        if not body:
            return None

        # Look for first string literal in function body
        for child in body.named_children()[:3]:  # Check first few statements
            if child.type in ('string', 'string_literal'):
                # Clean up the docstring
                docstring = child.text.strip('\'"')
                return docstring[:200] + "..." if len(docstring) > 200 else docstring

        return None

    def _estimate_complexity(self, code: str) -> int:
        """Estimate cyclomatic complexity of function"""
        # Simple heuristic based on control flow keywords
        complexity_keywords = [
            'if', 'elif', 'else', 'for', 'while', 'try', 'except', 'finally',
            'with', 'and', 'or', 'break', 'continue', 'return', 'yield',
            'raise', 'assert'
        ]

        complexity = 1  # Base complexity
        for keyword in complexity_keywords:
            # Count occurrences of keywords (simple regex)
            pattern = r'\b' + re.escape(keyword) + r'\b'
            matches = len(re.findall(pattern, code, re.IGNORECASE))

            # Weight different keywords differently
            if keyword in ('if', 'elif', 'for', 'while'):
                complexity += matches
            elif keyword in ('and', 'or'):
                complexity += matches * 0.5
            else:
                complexity += matches * 0.25

        return max(1, int(complexity))

    def _is_in_class(self) -> bool:
        """Check if current scope is inside a class"""
        scope = self.current_scope
        while scope:
            if scope.name != "<module>" and not any(
                scope.name == s.name for s in self.scopes if s.level < scope.level
            ):
                # Heuristic: if scope name starts with uppercase, likely a class
                if scope.name[0].isupper():
                    return True
            scope = scope.parent
        return False

    def resolve_call_target(self, call_expr: CallExpression) -> Optional[str]:
        """Resolve function call to its qualified name"""
        func_name = call_expr.function_name
        qualified_name = call_expr.qualified_name

        # Try exact match first
        resolved = self.current_scope.resolve_name(func_name)
        if resolved:
            return resolved

        # Try qualified name resolution
        if '.' in qualified_name:
            return self._resolve_attribute_name_from_string(qualified_name)

        # Check if it's an imported function
        if func_name in self.imports:
            return self.imports[func_name]

        # Check if it's a builtin or external function
        if self._is_builtin_function(func_name):
            return f"<builtin>.{func_name}"

        # Return as-is if we can't resolve (will be marked as unresolved)
        return qualified_name if qualified_name else func_name

    def _resolve_attribute_name_from_string(self, attr_string: str) -> Optional[str]:
        """Resolve dotted attribute name from string"""
        parts = attr_string.split('.')
        if len(parts) < 2:
            return attr_string

        base = parts[0]

        # Check imports
        if base in self.imports:
            return f"{self.imports[base]}.{'.'.join(parts[1:])}"
        elif base in self.module_imports:
            return attr_string

        # Try to resolve base in scope
        resolved_base = self.current_scope.resolve_name(base)
        if resolved_base:
            return f"{resolved_base}.{'.'.join(parts[1:])}"

        return attr_string

    def _is_builtin_function(self, func_name: str) -> bool:
        """Check if function name is a Python builtin"""
        builtins = {
            'print', 'len', 'str', 'int', 'float', 'bool', 'list', 'dict', 'set', 'tuple',
            'range', 'enumerate', 'zip', 'map', 'filter', 'sorted', 'reversed',
            'min', 'max', 'sum', 'any', 'all', 'abs', 'round', 'pow',
            'open', 'input', 'type', 'isinstance', 'hasattr', 'getattr', 'setattr',
            'dir', 'vars', 'globals', 'locals', 'eval', 'exec', 'compile',
            'iter', 'next', 'chr', 'ord', 'hex', 'oct', 'bin'
        }
        return func_name in builtins

    def get_scope_info(self) -> Dict[str, Any]:
        """Get information about discovered scopes"""
        return {
            'total_scopes': len(self.scopes),
            'max_nesting_level': max(scope.level for scope in self.scopes) if self.scopes else 0,
            'functions_per_scope': {
                scope.name: len(scope.symbols) for scope in self.scopes
            },
            'imports_discovered': len(self.imports),
            'module_imports': list(self.module_imports)
        }