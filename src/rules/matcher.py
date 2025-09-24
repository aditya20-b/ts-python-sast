"""
Pattern matching logic for security rules
"""

import re
from typing import List, Optional, Any, Union
from ..parsing.ast_utils import ASTNode, CallExpression, FunctionDef, ImportStatement
from .models import Pattern, CallPattern, ArgumentCondition, PatternType


class PatternMatcher:
    """Matches AST nodes against rule patterns"""

    def match_pattern(self, node: ASTNode, pattern: Pattern) -> bool:
        """Check if a node matches a pattern"""
        if pattern.kind == PatternType.CALL:
            return self._match_call_pattern(node, pattern)
        elif pattern.kind == PatternType.ASSIGNMENT:
            return self._match_assignment_pattern(node, pattern)
        elif pattern.kind == PatternType.IMPORT:
            return self._match_import_pattern(node, pattern)
        elif pattern.kind == PatternType.STRING_LITERAL:
            return self._match_string_literal_pattern(node, pattern)
        elif pattern.kind == PatternType.REGEX:
            return self._match_regex_pattern(node, pattern)
        else:
            return False

    def _match_call_pattern(self, node: ASTNode, pattern: Pattern) -> bool:
        """Match call expressions against call patterns"""
        if node.type != 'call':
            return False

        try:
            call = CallExpression(node.node, node.source_code)
        except ValueError:
            return False

        # Check if pattern has callee specification
        if pattern.callee:
            return self._match_call_expression(call, pattern.callee)

        # Simple name matching
        if pattern.name:
            return call.function_name == pattern.name

        return False

    def _match_call_expression(self, call: CallExpression, call_pattern: CallPattern) -> bool:
        """Match call expression against call pattern"""
        # Check exact name match
        if call_pattern.name:
            if call.function_name != call_pattern.name:
                return False

        # Check qualified name match
        if call_pattern.qualified_name:
            if call.qualified_name != call_pattern.qualified_name:
                return False

        # Check anyOf names
        if call_pattern.anyOf:
            qualified_name = call.qualified_name
            function_name = call.function_name
            if not any(name in [qualified_name, function_name] for name in call_pattern.anyOf):
                return False

        # Check module match
        if call_pattern.module:
            qualified_name = call.qualified_name
            if not qualified_name.startswith(call_pattern.module + '.'):
                return False

        # Check argument conditions
        if call_pattern.args:
            for arg_condition in call_pattern.args:
                if not self._match_argument_condition(call, arg_condition):
                    return False

        return True

    def _match_argument_condition(self, call: CallExpression, condition: ArgumentCondition) -> bool:
        """Check if a call matches an argument condition"""
        # Handle keyword arguments
        if condition.name:
            arg_value = call.get_keyword_argument(condition.name)

            # Check if argument is present
            if condition.present is not None:
                is_present = arg_value is not None
                if condition.present != is_present:
                    return False

            # If argument should be present but isn't found
            if arg_value is None and (condition.equals is not None or
                                     condition.contains is not None or
                                     condition.regex is not None):
                return False

            # Check exact value match
            if condition.equals is not None and arg_value:
                arg_text = arg_value.text.strip()

                # Handle different value types
                if isinstance(condition.equals, bool):
                    return arg_text.lower() in ['true', 'false'] and \
                           (arg_text.lower() == 'true') == condition.equals
                elif isinstance(condition.equals, str):
                    # Remove quotes from string literals
                    if arg_text.startswith(("'", '"')) and arg_text.endswith(("'", '"')):
                        arg_text = arg_text[1:-1]
                    return arg_text == condition.equals
                else:
                    return arg_text == str(condition.equals)

            # Check contains match
            if condition.contains is not None and arg_value:
                return condition.contains in arg_value.text

            # Check regex match
            if condition.regex is not None and arg_value:
                return bool(re.search(condition.regex, arg_value.text))

        return True

    def _match_assignment_pattern(self, node: ASTNode, pattern: Pattern) -> bool:
        """Match assignment statements"""
        if node.type not in ['assignment', 'augmented_assignment']:
            return False

        # Simple name matching for now
        if pattern.name:
            return pattern.name in node.text

        return False

    def _match_import_pattern(self, node: ASTNode, pattern: Pattern) -> bool:
        """Match import statements"""
        if node.type not in ['import_statement', 'import_from_statement']:
            return False

        try:
            import_stmt = ImportStatement(node.node, node.source_code)
        except ValueError:
            return False

        # Check module name
        if pattern.name:
            return pattern.name in [import_stmt.module_name] + import_stmt.imported_names

        return False

    def _match_string_literal_pattern(self, node: ASTNode, pattern: Pattern) -> bool:
        """Match string literals"""
        if node.type not in ['string', 'string_literal']:
            return False

        text = node.text

        # Check exact match
        if pattern.name:
            # Remove quotes from string
            content = text.strip('\'"')
            return pattern.name in content

        # Check regex match
        if pattern.regex:
            return bool(re.search(pattern.regex, text))

        return False

    def _match_regex_pattern(self, node: ASTNode, pattern: Pattern) -> bool:
        """Match any node text against regex"""
        if not pattern.regex:
            return False

        return bool(re.search(pattern.regex, node.text))

    def find_matches(self, ast: ASTNode, patterns: List[Pattern]) -> List[ASTNode]:
        """Find all nodes that match any of the given patterns"""
        matches = []

        def search_node(node: ASTNode) -> None:
            # Check if current node matches any pattern
            for pattern in patterns:
                if self.match_pattern(node, pattern):
                    matches.append(node)
                    break  # Don't match multiple patterns on same node

            # Recursively search children
            for child in node.children():
                search_node(child)

        search_node(ast)
        return matches

    def get_call_targets(self, ast: ASTNode) -> List[str]:
        """Extract all unique function call targets from AST"""
        targets = set()

        def extract_calls(node: ASTNode) -> None:
            if node.type == 'call':
                try:
                    call = CallExpression(node.node, node.source_code)
                    targets.add(call.qualified_name)
                except ValueError:
                    pass

            for child in node.children():
                extract_calls(child)

        extract_calls(ast)
        return list(targets)

    def analyze_string_content(self, node: ASTNode) -> dict:
        """Analyze string content for potential security issues"""
        if node.type not in ['string', 'string_literal']:
            return {}

        content = node.text.strip('\'"')
        analysis = {
            'length': len(content),
            'contains_sql_keywords': bool(re.search(
                r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b',
                content, re.IGNORECASE
            )),
            'contains_shell_metacharacters': bool(re.search(
                r'[;&|`$(){}[\]]', content
            )),
            'looks_like_url': bool(re.match(
                r'https?://', content, re.IGNORECASE
            )),
            'contains_secrets': self._detect_secrets(content)
        }

        return analysis

    def _detect_secrets(self, content: str) -> bool:
        """Basic secret detection in string content"""
        secret_patterns = [
            r'(?i)(password|passwd|pwd|secret|key|token|api[_-]?key)',
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
            r'[0-9a-f]{32}',      # MD5-like hash
            r'[0-9a-f]{40}',      # SHA1-like hash
            r'[A-Za-z0-9+/]{40,}={0,2}',  # Base64-like
        ]

        for pattern in secret_patterns:
            if re.search(pattern, content):
                return True

        return False