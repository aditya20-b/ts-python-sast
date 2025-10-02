"""
Taint sink configuration and detection

Enhanced with multi-tier detection:
1. Exact match from known list (highest confidence)
2. Heuristic with module context (high confidence)
3. Heuristic pattern matching (medium confidence)
"""

from typing import List, Dict, Set, Optional, Tuple
from ..parsing.ast_utils import ASTNode, CallExpression
from .models import TaintSink, SinkType
from .heuristics import HeuristicSinkDetector, HeuristicConfidence


class SinkConfig:
    """Configuration and detection of taint sinks"""

    def __init__(self, enable_heuristics: bool = True):
        self.sinks: Dict[str, TaintSink] = {}
        self.enable_heuristics = enable_heuristics
        self.heuristic_detector = HeuristicSinkDetector() if enable_heuristics else None
        self._initialize_default_sinks()

    def _initialize_default_sinks(self) -> None:
        """Initialize default taint sinks"""
        default_sinks = [
            # Command execution sinks
            TaintSink(
                name="os.system",
                qualified_name="os.system",
                sink_type=SinkType.COMMAND_EXEC,
                severity="high",
                patterns=["os.system"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="os.popen",
                qualified_name="os.popen",
                sink_type=SinkType.COMMAND_EXEC,
                severity="high",
                patterns=["os.popen"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="subprocess.run",
                qualified_name="subprocess.run",
                sink_type=SinkType.COMMAND_EXEC,
                severity="high",
                patterns=["subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="subprocess.Popen",
                qualified_name="subprocess.Popen",
                sink_type=SinkType.COMMAND_EXEC,
                severity="high",
                patterns=["subprocess.Popen"],
                vulnerable_params=[0]
            ),

            # Code evaluation sinks
            TaintSink(
                name="eval",
                sink_type=SinkType.CODE_EVAL,
                severity="critical",
                patterns=["eval"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="exec",
                sink_type=SinkType.CODE_EVAL,
                severity="critical",
                patterns=["exec"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="compile",
                sink_type=SinkType.CODE_EVAL,
                severity="high",
                patterns=["compile"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="__import__",
                sink_type=SinkType.CODE_EVAL,
                severity="high",
                patterns=["__import__"],
                vulnerable_params=[0]
            ),

            # SQL execution sinks
            TaintSink(
                name="cursor.execute",
                sink_type=SinkType.SQL_EXEC,
                severity="high",
                patterns=["cursor.execute", "connection.execute", "db.execute"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="cursor.executemany",
                sink_type=SinkType.SQL_EXEC,
                severity="high",
                patterns=["cursor.executemany", "connection.executemany"],
                vulnerable_params=[0]
            ),

            # File write sinks
            TaintSink(
                name="open().write",
                sink_type=SinkType.FILE_WRITE,
                severity="medium",
                patterns=["write", "writelines"],
                vulnerable_params=[0]
            ),

            # Template rendering sinks
            TaintSink(
                name="render_template_string",
                qualified_name="flask.render_template_string",
                sink_type=SinkType.TEMPLATE_RENDER,
                severity="high",
                patterns=["render_template_string", "flask.render_template_string"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="Template().render",
                sink_type=SinkType.TEMPLATE_RENDER,
                severity="medium",
                patterns=["Template", "Jinja2.Template"],
                vulnerable_params=[0]
            ),

            # Network sinks
            TaintSink(
                name="requests.get",
                qualified_name="requests.get",
                sink_type=SinkType.HTTP_REQUEST,
                severity="medium",
                patterns=["requests.get", "requests.post", "requests.request"],
                vulnerable_params=[0]
            ),
            TaintSink(
                name="urllib.urlopen",
                sink_type=SinkType.HTTP_REQUEST,
                severity="medium",
                patterns=["urllib.request.urlopen", "urllib.urlopen", "urllib2.urlopen"],
                vulnerable_params=[0]
            ),

            # Serialization sinks
            TaintSink(
                name="pickle.loads",
                qualified_name="pickle.loads",
                sink_type=SinkType.SERIALIZATION,
                severity="high",
                patterns=["pickle.loads", "pickle.load", "cPickle.loads"],
                vulnerable_params=[0]
            ),

            # Logging sinks (PII leak)
            TaintSink(
                name="logging",
                sink_type=SinkType.LOG_OUTPUT,
                severity="low",
                patterns=["logging.info", "logging.debug", "logging.warning", "logging.error"],
                vulnerable_params=[0]
            ),

            # Path traversal sinks
            TaintSink(
                name="os.path.join",
                qualified_name="os.path.join",
                sink_type=SinkType.PATH_TRAVERSAL,
                severity="medium",
                patterns=["os.path.join", "pathlib.Path"],
                vulnerable_params=[0, 1]
            ),
        ]

        for sink in default_sinks:
            self.sinks[sink.name] = sink

    def add_sink(self, sink: TaintSink) -> None:
        """Add a custom taint sink"""
        self.sinks[sink.name] = sink

    def is_sink(
        self,
        call_expr: CallExpression,
        module_context: Optional[str] = None
    ) -> Optional[TaintSink]:
        """
        Check if a call expression is a taint sink using multi-tier detection

        Args:
            call_expr: The function call to check
            module_context: Optional module name for context-aware detection

        Returns:
            TaintSink if detected, with confidence score set
        """
        func_name = call_expr.function_name
        qualified_name = call_expr.qualified_name

        # Tier 1: Exact match from known list (highest confidence)
        for sink in self.sinks.values():
            # Check qualified name first
            if sink.qualified_name and qualified_name == sink.qualified_name:
                sink.confidence = HeuristicConfidence.VERY_HIGH.value
                return sink

            # Check function name
            if func_name == sink.name:
                sink.confidence = HeuristicConfidence.VERY_HIGH.value
                return sink

            # Check patterns
            for pattern in sink.patterns:
                if pattern in qualified_name or pattern == func_name:
                    sink.confidence = HeuristicConfidence.VERY_HIGH.value
                    return sink

        # Tier 2 & 3: Heuristic detection (if enabled)
        if self.enable_heuristics and self.heuristic_detector:
            result = self.heuristic_detector.detect_sink_type(
                func_name,
                qualified_name,
                module_context
            )

            if result:
                sink_type, severity, confidence = result

                # Create a dynamic TaintSink
                return TaintSink(
                    name=qualified_name or func_name,
                    qualified_name=qualified_name,
                    sink_type=sink_type,
                    severity=severity,
                    patterns=[func_name],
                    vulnerable_params=[0],  # Default: first param is vulnerable
                    confidence=confidence
                )

        return None

    def get_sink_by_type(self, sink_type: SinkType) -> List[TaintSink]:
        """Get all sinks of a specific type"""
        return [s for s in self.sinks.values() if s.sink_type == sink_type]

    def get_all_sinks(self) -> List[TaintSink]:
        """Get all configured sinks"""
        return list(self.sinks.values())

    def detect_sinks_in_node(self, node: ASTNode) -> List[tuple]:
        """Detect all taint sinks in an AST node

        Returns:
            List of (sink, call_expr, location) tuples
        """
        detected_sinks = []

        def visit_node(n: ASTNode) -> None:
            # Check function calls
            if n.type == 'call':
                try:
                    call_expr = CallExpression(n.node, n.source_code)
                    sink = self.is_sink(call_expr)
                    if sink:
                        location = (n.start_point[0] + 1, n.start_point[1] + 1)
                        detected_sinks.append((sink, call_expr, location))
                except ValueError:
                    pass

            # Recursively visit children
            for child in n.children():
                visit_node(child)

        visit_node(node)
        return detected_sinks

    def get_vulnerable_params(self, sink_name: str) -> List[int]:
        """Get list of vulnerable parameter indices for a sink"""
        sink = self.sinks.get(sink_name)
        return sink.vulnerable_params if sink else []

    def get_sink_severity(self, sink_name: str) -> str:
        """Get severity level for a sink"""
        sink = self.sinks.get(sink_name)
        return sink.severity if sink else "medium"

    def is_vulnerable_argument(self, sink: TaintSink, arg_index: int) -> bool:
        """Check if a specific argument position is vulnerable for this sink"""
        # If no vulnerable params specified, assume all are vulnerable
        if not sink.vulnerable_params:
            return True

        return arg_index in sink.vulnerable_params