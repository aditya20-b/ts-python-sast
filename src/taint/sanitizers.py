"""
Sanitizer configuration and detection
"""

from typing import List, Dict, Set, Optional
from ..parsing.ast_utils import ASTNode, CallExpression
from .models import Sanitizer, SanitizerType, TaintLabel


class SanitizerConfig:
    """Configuration and detection of sanitizers"""

    def __init__(self):
        self.sanitizers: Dict[str, Sanitizer] = {}
        self._initialize_default_sanitizers()

    def _initialize_default_sanitizers(self) -> None:
        """Initialize default sanitizers"""
        default_sanitizers = [
            # Shell escaping
            Sanitizer(
                name="shlex.quote",
                qualified_name="shlex.quote",
                sanitizer_type=SanitizerType.SHELL_ESCAPE,
                removes_labels=[TaintLabel.USER, TaintLabel.FILE, TaintLabel.ENV],
                patterns=["shlex.quote", "pipes.quote"]
            ),

            # HTML escaping
            Sanitizer(
                name="html.escape",
                qualified_name="html.escape",
                sanitizer_type=SanitizerType.HTML_ESCAPE,
                removes_labels=[TaintLabel.USER, TaintLabel.FILE],
                patterns=["html.escape", "cgi.escape", "markupsafe.escape"]
            ),

            # URL encoding
            Sanitizer(
                name="urllib.parse.quote",
                qualified_name="urllib.parse.quote",
                sanitizer_type=SanitizerType.URL_ENCODE,
                removes_labels=[TaintLabel.USER],
                patterns=["urllib.parse.quote", "urllib.quote", "urllib.parse.quote_plus"]
            ),

            # Path normalization
            Sanitizer(
                name="os.path.normpath",
                qualified_name="os.path.normpath",
                sanitizer_type=SanitizerType.PATH_NORMALIZE,
                removes_labels=[TaintLabel.USER, TaintLabel.FILE],
                patterns=["os.path.normpath", "os.path.abspath", "Path.resolve"]
            ),

            # Type casting (removes string-based attacks)
            Sanitizer(
                name="int",
                sanitizer_type=SanitizerType.TYPE_CAST,
                removes_labels=[TaintLabel.USER],
                patterns=["int"]
            ),
            Sanitizer(
                name="float",
                sanitizer_type=SanitizerType.TYPE_CAST,
                removes_labels=[TaintLabel.USER],
                patterns=["float"]
            ),
            Sanitizer(
                name="str.isdigit",
                sanitizer_type=SanitizerType.REGEX_VALIDATE,
                removes_labels=[TaintLabel.USER],
                patterns=["isdigit", "isalpha", "isalnum"]
            ),

            # Regex validation
            Sanitizer(
                name="re.match",
                qualified_name="re.match",
                sanitizer_type=SanitizerType.REGEX_VALIDATE,
                removes_labels=[TaintLabel.USER],
                patterns=["re.match", "re.fullmatch", "re.search"]
            ),
        ]

        for sanitizer in default_sanitizers:
            self.sanitizers[sanitizer.name] = sanitizer

    def add_sanitizer(self, sanitizer: Sanitizer) -> None:
        """Add a custom sanitizer"""
        self.sanitizers[sanitizer.name] = sanitizer

    def is_sanitizer(self, call_expr: CallExpression) -> Optional[Sanitizer]:
        """Check if a call expression is a sanitizer"""
        func_name = call_expr.function_name
        qualified_name = call_expr.qualified_name

        # Check direct matches
        for sanitizer in self.sanitizers.values():
            # Check qualified name first
            if sanitizer.qualified_name and qualified_name == sanitizer.qualified_name:
                return sanitizer

            # Check function name
            if func_name == sanitizer.name:
                return sanitizer

            # Check patterns
            for pattern in sanitizer.patterns:
                if pattern in qualified_name or pattern == func_name:
                    return sanitizer

        return None

    def is_parameterized_query(self, call_expr: CallExpression) -> bool:
        """Check if a SQL query is parameterized (safe)"""
        # Check if this is a cursor.execute or similar
        func_name = call_expr.function_name
        qualified_name = call_expr.qualified_name

        if 'execute' not in func_name.lower():
            return False

        # Check if it has multiple arguments (parameterized)
        args = call_expr.arguments
        if len(args) >= 2:
            # Second argument is parameters - this is safe
            return True

        # Check if first argument is a constant string (no formatting)
        if args:
            first_arg = args[0]
            # Simple heuristic: if it contains %s or ?, it might be parameterized
            if '%s' in first_arg.text or '?' in first_arg.text:
                # But only if no string formatting is used
                if 'f"' not in first_arg.text and '.format(' not in first_arg.text and '%' not in first_arg.text[:-5]:
                    return True

        return False

    def get_sanitizer_by_type(self, sanitizer_type: SanitizerType) -> List[Sanitizer]:
        """Get all sanitizers of a specific type"""
        return [s for s in self.sanitizers.values() if s.sanitizer_type == sanitizer_type]

    def get_all_sanitizers(self) -> List[Sanitizer]:
        """Get all configured sanitizers"""
        return list(self.sanitizers.values())

    def detect_sanitizers_in_node(self, node: ASTNode) -> List[tuple]:
        """Detect all sanitizers in an AST node

        Returns:
            List of (sanitizer, call_expr, location) tuples
        """
        detected_sanitizers = []

        def visit_node(n: ASTNode) -> None:
            # Check function calls
            if n.type == 'call':
                try:
                    call_expr = CallExpression(n.node, n.source_code)
                    sanitizer = self.is_sanitizer(call_expr)
                    if sanitizer:
                        location = (n.start_point[0] + 1, n.start_point[1] + 1)
                        detected_sanitizers.append((sanitizer, call_expr, location))

                    # Also check for parameterized queries
                    if self.is_parameterized_query(call_expr):
                        # Create a virtual sanitizer for parameterized SQL
                        param_sanitizer = Sanitizer(
                            name="parameterized_query",
                            sanitizer_type=SanitizerType.SQL_PARAMETERIZE,
                            removes_labels=[TaintLabel.USER, TaintLabel.FILE],
                            patterns=[]
                        )
                        location = (n.start_point[0] + 1, n.start_point[1] + 1)
                        detected_sanitizers.append((param_sanitizer, call_expr, location))

                except ValueError:
                    pass

            # Recursively visit children
            for child in n.children():
                visit_node(child)

        visit_node(node)
        return detected_sanitizers

    def removes_taint_label(self, sanitizer: Sanitizer, label: TaintLabel) -> bool:
        """Check if a sanitizer removes a specific taint label"""
        return label in sanitizer.removes_labels

    def get_removed_labels(self, sanitizer_name: str) -> Set[TaintLabel]:
        """Get set of taint labels removed by a sanitizer"""
        sanitizer = self.sanitizers.get(sanitizer_name)
        return set(sanitizer.removes_labels) if sanitizer else set()

    def is_effective_against(self, sanitizer: Sanitizer, labels: Set[TaintLabel]) -> bool:
        """Check if sanitizer is effective against given taint labels"""
        removed = set(sanitizer.removes_labels)
        return bool(removed.intersection(labels))