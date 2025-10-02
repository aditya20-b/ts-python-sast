"""
Module import tracking for context-aware taint analysis
"""

from typing import Dict, Set, Optional, List
from ..parsing.ast_utils import ASTNode, ImportStatement


class ModuleTracker:
    """Track imported modules for context-aware detection"""

    def __init__(self):
        self.imported_modules: Dict[str, str] = {}  # alias -> full_name
        self.module_aliases: Dict[str, str] = {}     # full_name -> alias
        self.imported_names: Dict[str, str] = {}     # name -> module

    def track_imports(self, ast_root: ASTNode) -> None:
        """Extract all imports from AST"""
        self.imported_modules.clear()
        self.module_aliases.clear()
        self.imported_names.clear()

        def visit_node(node: ASTNode) -> None:
            if node.type == 'import_statement':
                self._process_import(node)
            elif node.type == 'import_from_statement':
                self._process_from_import(node)

            for child in node.children():
                visit_node(child)

        visit_node(ast_root)

    def _process_import(self, node: ASTNode) -> None:
        """Process 'import module' or 'import module as alias'"""
        # import os
        # import subprocess as sp
        for child in node.children():
            if child.type == 'dotted_name':
                module_name = child.text
                self.imported_modules[module_name] = module_name
                self.module_aliases[module_name] = module_name

            elif child.type == 'aliased_import':
                # import module as alias
                name_node = child.child_by_field_name('name')
                alias_node = child.child_by_field_name('alias')

                if name_node and alias_node:
                    module_name = name_node.text
                    alias = alias_node.text
                    self.imported_modules[alias] = module_name
                    self.module_aliases[module_name] = alias

    def _process_from_import(self, node: ASTNode) -> None:
        """Process 'from module import name'"""
        # from os import system
        # from flask import request
        module_node = node.child_by_field_name('module_name')
        if not module_node:
            return

        module_name = module_node.text

        # Find all imported names
        for child in node.children():
            if child.type == 'dotted_name' and child != module_node:
                name = child.text
                self.imported_names[name] = module_name

            elif child.type == 'aliased_import':
                name_node = child.child_by_field_name('name')
                alias_node = child.child_by_field_name('alias')

                if name_node:
                    name = name_node.text
                    if alias_node:
                        alias = alias_node.text
                        self.imported_names[alias] = module_name
                    else:
                        self.imported_names[name] = module_name

    def get_module_for_call(self, qualified_name: str) -> Optional[str]:
        """
        Get the actual module name for a function call

        Examples:
            - os.system -> 'os' (if os is imported)
            - sp.run -> 'subprocess' (if imported as sp)
            - system -> 'os' (if from os import system)
        """
        if '.' in qualified_name:
            # Qualified call like os.system or sp.run
            parts = qualified_name.split('.')
            prefix = parts[0]

            # Check if prefix is an imported module or alias
            if prefix in self.imported_modules:
                return self.imported_modules[prefix]

        else:
            # Unqualified call like system()
            # Check if it was imported from somewhere
            if qualified_name in self.imported_names:
                return self.imported_names[qualified_name]

        return None

    def is_module_imported(self, module_name: str) -> bool:
        """Check if a module is imported"""
        return (module_name in self.imported_modules.values() or
                module_name in self.imported_modules.keys())

    def get_imported_modules(self) -> Set[str]:
        """Get all imported module names (not aliases)"""
        return set(self.imported_modules.values())

    def get_imported_names(self) -> Dict[str, str]:
        """Get all imported names and their source modules"""
        return self.imported_names.copy()

    def resolve_module_name(self, name: str) -> str:
        """
        Resolve a name to its full module path

        Examples:
            - 'os' -> 'os'
            - 'sp' -> 'subprocess' (if imported as sp)
            - 'system' -> 'os.system' (if from os import system)
        """
        # Check if it's a module alias
        if name in self.imported_modules:
            return self.imported_modules[name]

        # Check if it's an imported name
        if name in self.imported_names:
            module = self.imported_names[name]
            return f"{module}.{name}"

        return name

    def get_dangerous_imports(self) -> List[tuple]:
        """
        Get all dangerous modules that are imported

        Returns:
            List of (module_name, categories) tuples
        """
        from .heuristics import DangerousModuleTaxonomy

        dangerous = []
        for module_name in self.get_imported_modules():
            categories = DangerousModuleTaxonomy.classify_module(module_name)
            if categories:
                dangerous.append((module_name, categories))

        return dangerous

    def __repr__(self) -> str:
        return (f"ModuleTracker(modules={len(self.imported_modules)}, "
                f"names={len(self.imported_names)})")
