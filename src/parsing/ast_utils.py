"""
AST utilities and node wrappers for tree-sitter nodes
"""

from typing import List, Optional, Any, Dict
import tree_sitter


class ASTNode:
    """Wrapper for tree-sitter nodes with convenience methods"""

    def __init__(self, node: tree_sitter.Node, source_code: bytes):
        self.node = node
        self.source_code = source_code

    @property
    def type(self) -> str:
        """Node type (e.g., 'call', 'function_definition')"""
        return self.node.type

    @property
    def text(self) -> str:
        """Text content of the node"""
        return self.node.text.decode('utf-8')

    @property
    def start_byte(self) -> int:
        """Start byte position in source"""
        return self.node.start_byte

    @property
    def end_byte(self) -> int:
        """End byte position in source"""
        return self.node.end_byte

    @property
    def start_point(self) -> tuple:
        """Start line/column position"""
        return self.node.start_point

    @property
    def end_point(self) -> tuple:
        """End line/column position"""
        return self.node.end_point

    def children(self) -> List['ASTNode']:
        """Get child nodes"""
        return [ASTNode(child, self.source_code) for child in self.node.children]

    def child_by_field_name(self, field_name: str) -> Optional['ASTNode']:
        """Get child by field name"""
        child = self.node.child_by_field_name(field_name)
        return ASTNode(child, self.source_code) if child else None

    def named_children(self) -> List['ASTNode']:
        """Get named child nodes (excluding anonymous nodes like punctuation)"""
        return [ASTNode(child, self.source_code) for child in self.node.named_children]

    def find_children_by_type(self, node_type: str) -> List['ASTNode']:
        """Find all children of a specific type"""
        result = []
        for child in self.children():
            if child.type == node_type:
                result.append(child)
            result.extend(child.find_children_by_type(node_type))
        return result

    def __repr__(self) -> str:
        return f"ASTNode(type={self.type}, text={self.text[:50]!r})"


class CallExpression(ASTNode):
    """Specialized wrapper for function/method calls"""

    def __init__(self, node: tree_sitter.Node, source_code: bytes):
        super().__init__(node, source_code)
        if node.type != 'call':
            raise ValueError(f"Expected 'call' node, got '{node.type}'")

    @property
    def function(self) -> Optional[ASTNode]:
        """The function being called"""
        return self.child_by_field_name('function')

    @property
    def arguments(self) -> List[ASTNode]:
        """List of argument nodes"""
        args_node = self.child_by_field_name('arguments')
        if not args_node:
            return []
        return args_node.named_children()

    @property
    def function_name(self) -> str:
        """Extract function name (handles simple cases)"""
        func = self.function
        if not func:
            return ""

        if func.type == 'identifier':
            return func.text
        elif func.type == 'attribute':
            # For calls like obj.method()
            attr = func.child_by_field_name('attribute')
            return attr.text if attr else ""
        else:
            return func.text

    @property
    def qualified_name(self) -> str:
        """Get full qualified name (e.g., 'subprocess.run')"""
        func = self.function
        if not func:
            return ""

        if func.type == 'attribute':
            obj = func.child_by_field_name('object')
            attr = func.child_by_field_name('attribute')
            if obj and attr:
                # Recursively build qualified name
                if obj.type == 'identifier':
                    return f"{obj.text}.{attr.text}"
                elif obj.type == 'attribute':
                    obj_qualified = CallExpression._get_qualified_name(obj)
                    return f"{obj_qualified}.{attr.text}"

        return self.function_name

    @staticmethod
    def _get_qualified_name(node: ASTNode) -> str:
        """Helper to recursively get qualified names"""
        if node.type == 'identifier':
            return node.text
        elif node.type == 'attribute':
            obj = node.child_by_field_name('object')
            attr = node.child_by_field_name('attribute')
            if obj and attr:
                return f"{CallExpression._get_qualified_name(obj)}.{attr.text}"
        return node.text

    def get_keyword_argument(self, keyword: str) -> Optional[ASTNode]:
        """Get value of a keyword argument"""
        for arg in self.arguments:
            if arg.type == 'keyword_argument':
                name_node = arg.child_by_field_name('name')
                if name_node and name_node.text == keyword:
                    return arg.child_by_field_name('value')
        return None

    def has_keyword_argument(self, keyword: str) -> bool:
        """Check if keyword argument is present"""
        return self.get_keyword_argument(keyword) is not None


class FunctionDef(ASTNode):
    """Specialized wrapper for function definitions"""

    def __init__(self, node: tree_sitter.Node, source_code: bytes):
        super().__init__(node, source_code)
        if node.type != 'function_definition':
            raise ValueError(f"Expected 'function_definition' node, got '{node.type}'")

    @property
    def name(self) -> str:
        """Function name"""
        name_node = self.child_by_field_name('name')
        return name_node.text if name_node else ""

    @property
    def parameters(self) -> List[ASTNode]:
        """Function parameters"""
        params_node = self.child_by_field_name('parameters')
        if not params_node:
            return []
        return params_node.named_children()

    @property
    def body(self) -> Optional[ASTNode]:
        """Function body"""
        return self.child_by_field_name('body')

    def get_calls(self) -> List[CallExpression]:
        """Get all function calls within this function"""
        calls = []
        body = self.body
        if body:
            call_nodes = body.find_children_by_type('call')
            calls = [CallExpression(node.node, self.source_code) for node in call_nodes]
        return calls


class ImportStatement(ASTNode):
    """Specialized wrapper for import statements"""

    def __init__(self, node: tree_sitter.Node, source_code: bytes):
        super().__init__(node, source_code)
        if node.type not in ('import_statement', 'import_from_statement'):
            raise ValueError(f"Expected import node, got '{node.type}'")

    @property
    def module_name(self) -> str:
        """Name of the imported module"""
        if self.type == 'import_statement':
            # import module
            dotted_name = self.child_by_field_name('name')
            return dotted_name.text if dotted_name else ""
        else:
            # from module import ...
            module = self.child_by_field_name('module_name')
            return module.text if module else ""

    @property
    def imported_names(self) -> List[str]:
        """List of imported names"""
        names = []
        if self.type == 'import_statement':
            # import module [as alias]
            dotted_name = self.child_by_field_name('name')
            if dotted_name:
                names.append(dotted_name.text)
        else:
            # from module import name1, name2
            for child in self.named_children():
                if child.type == 'dotted_name':
                    names.append(child.text)
                elif child.type == 'aliased_import':
                    name_node = child.child_by_field_name('name')
                    if name_node:
                        names.append(name_node.text)
        return names