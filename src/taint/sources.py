"""
Taint source configuration and detection
"""

from typing import List, Dict, Set, Optional
from ..parsing.ast_utils import ASTNode, CallExpression
from .models import TaintSource, SourceType, TaintLabel


class SourceConfig:
    """Configuration and detection of taint sources"""

    def __init__(self):
        self.sources: Dict[str, TaintSource] = {}
        self._initialize_default_sources()

    def _initialize_default_sources(self) -> None:
        """Initialize default taint sources"""
        default_sources = [
            # User input functions
            TaintSource(
                name="input",
                source_type=SourceType.USER_INPUT,
                taint_label=TaintLabel.USER,
                patterns=["input", "raw_input"],
                confidence=1.0
            ),

            # Command line arguments
            TaintSource(
                name="sys.argv",
                qualified_name="sys.argv",
                source_type=SourceType.SYS_ARGV,
                taint_label=TaintLabel.USER,
                patterns=["sys.argv"],
                confidence=1.0
            ),

            # Environment variables
            TaintSource(
                name="os.environ",
                qualified_name="os.environ",
                source_type=SourceType.ENV_VAR,
                taint_label=TaintLabel.ENV,
                patterns=["os.environ", "os.getenv"],
                confidence=1.0
            ),

            # Flask request sources
            TaintSource(
                name="flask.request.args",
                qualified_name="flask.request.args",
                source_type=SourceType.FLASK_REQUEST,
                taint_label=TaintLabel.USER,
                patterns=["request.args", "flask.request.args"],
                confidence=0.9
            ),
            TaintSource(
                name="flask.request.form",
                qualified_name="flask.request.form",
                source_type=SourceType.FLASK_REQUEST,
                taint_label=TaintLabel.USER,
                patterns=["request.form", "flask.request.form"],
                confidence=0.9
            ),
            TaintSource(
                name="flask.request.json",
                qualified_name="flask.request.json",
                source_type=SourceType.FLASK_REQUEST,
                taint_label=TaintLabel.USER,
                patterns=["request.json", "flask.request.json"],
                confidence=0.9
            ),
            TaintSource(
                name="flask.request.data",
                qualified_name="flask.request.data",
                source_type=SourceType.FLASK_REQUEST,
                taint_label=TaintLabel.USER,
                patterns=["request.data", "flask.request.data"],
                confidence=0.9
            ),

            # File reading
            TaintSource(
                name="open().read",
                source_type=SourceType.FILE_READ,
                taint_label=TaintLabel.FILE,
                patterns=["read", "readline", "readlines"],
                confidence=0.8
            ),

            # Network sources
            TaintSource(
                name="requests.get",
                qualified_name="requests.get",
                source_type=SourceType.NETWORK_READ,
                taint_label=TaintLabel.NETWORK,
                patterns=["requests.get", "requests.post", "requests.request"],
                confidence=0.8
            ),
            TaintSource(
                name="socket.recv",
                qualified_name="socket.recv",
                source_type=SourceType.NETWORK_READ,
                taint_label=TaintLabel.NETWORK,
                patterns=["socket.recv", "sock.recv"],
                confidence=0.9
            ),
        ]

        for source in default_sources:
            self.sources[source.name] = source

    def add_source(self, source: TaintSource) -> None:
        """Add a custom taint source"""
        self.sources[source.name] = source

    def is_source(self, call_expr: CallExpression) -> Optional[TaintSource]:
        """Check if a call expression is a taint source"""
        func_name = call_expr.function_name
        qualified_name = call_expr.qualified_name

        # Check direct matches
        for source in self.sources.values():
            # Check qualified name first
            if source.qualified_name and qualified_name == source.qualified_name:
                return source

            # Check function name
            if func_name == source.name:
                return source

            # Check patterns
            for pattern in source.patterns:
                if pattern in qualified_name or pattern == func_name:
                    return source

        return None

    def is_source_variable(self, var_name: str) -> Optional[TaintSource]:
        """Check if a variable access is a taint source (e.g., sys.argv)"""
        for source in self.sources.values():
            if source.qualified_name and var_name in source.qualified_name:
                return source

            for pattern in source.patterns:
                if pattern in var_name:
                    return source

        return None

    def get_source_by_type(self, source_type: SourceType) -> List[TaintSource]:
        """Get all sources of a specific type"""
        return [s for s in self.sources.values() if s.source_type == source_type]

    def get_all_sources(self) -> List[TaintSource]:
        """Get all configured sources"""
        return list(self.sources.values())

    def detect_sources_in_node(self, node: ASTNode) -> List[tuple]:
        """Detect all taint sources in an AST node

        Returns:
            List of (source, node, location) tuples
        """
        detected_sources = []

        def visit_node(n: ASTNode) -> None:
            # Check function calls
            if n.type == 'call':
                try:
                    call_expr = CallExpression(n.node, n.source_code)
                    source = self.is_source(call_expr)
                    if source:
                        location = (n.start_point[0] + 1, n.start_point[1] + 1)
                        detected_sources.append((source, n, location))
                except ValueError:
                    pass

            # Check attribute access (e.g., sys.argv, request.args)
            elif n.type == 'attribute':
                attr_text = n.text
                source = self.is_source_variable(attr_text)
                if source:
                    location = (n.start_point[0] + 1, n.start_point[1] + 1)
                    detected_sources.append((source, n, location))

            # Check subscript access (e.g., sys.argv[1], request.args['key'])
            elif n.type == 'subscript':
                subscript_obj = n.child_by_field_name('value')
                if subscript_obj:
                    obj_text = subscript_obj.text
                    source = self.is_source_variable(obj_text)
                    if source:
                        location = (n.start_point[0] + 1, n.start_point[1] + 1)
                        detected_sources.append((source, n, location))

            # Recursively visit children
            for child in n.children():
                visit_node(child)

        visit_node(node)
        return detected_sources

    def get_source_confidence(self, source_name: str) -> float:
        """Get confidence level for a source"""
        source = self.sources.get(source_name)
        return source.confidence if source else 0.0

    def get_source_label(self, source_name: str) -> Optional[TaintLabel]:
        """Get taint label for a source"""
        source = self.sources.get(source_name)
        return source.taint_label if source else None