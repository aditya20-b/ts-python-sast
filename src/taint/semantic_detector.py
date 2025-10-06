"""
Semantic taint detection using object tracking and module classification.

This approach is MORE semantic and LESS exhaustive than keyword matching:
1. Tracks object TYPES (file, socket, HTTP response) via constructors
2. ANY operation on I/O objects = tainted (works for obfuscated method names)
3. Module-scope classification (if subprocess imported, ALL subprocess.* = sink)
4. AST structural patterns (sys.argv subscript, not function name)

Dramatically reduces hardcoded lists while improving coverage.
"""

from typing import Dict, Set, Optional, List
from enum import Enum
from ..parsing.ast_utils import ASTNode, CallExpression


class ObjectType(Enum):
    """Types of objects that can be taint sources"""
    FILE_OBJECT = "file"
    SOCKET = "socket"
    HTTP_RESPONSE = "http_response"
    DATABASE_CURSOR = "database_cursor"
    PROCESS = "process"
    UNKNOWN = "unknown"


class IOObjectTracker:
    """
    Tracks I/O objects through variable assignments.

    Key insight: Instead of listing all read methods (read, readline, recv, etc.),
    track what TYPE each variable is. Then ANY operation on that type = tainted.
    """

    # Special web request object type
    WEB_REQUEST = ObjectType.HTTP_RESPONSE  # Reuse HTTP_RESPONSE for web requests

    # Minimal list of I/O constructors (unavoidable)
    IO_CONSTRUCTORS = {
        'open': ObjectType.FILE_OBJECT,
        'file': ObjectType.FILE_OBJECT,
        'io.open': ObjectType.FILE_OBJECT,
        'socket.socket': ObjectType.SOCKET,
        'socket.create_connection': ObjectType.SOCKET,
        'requests.get': ObjectType.HTTP_RESPONSE,
        'requests.post': ObjectType.HTTP_RESPONSE,
        'requests.request': ObjectType.HTTP_RESPONSE,
        'urllib.request.urlopen': ObjectType.HTTP_RESPONSE,
        'urllib2.urlopen': ObjectType.HTTP_RESPONSE,
        'http.client.HTTPConnection': ObjectType.HTTP_RESPONSE,
        'sqlite3.connect': ObjectType.DATABASE_CURSOR,
        'psycopg2.connect': ObjectType.DATABASE_CURSOR,
        'subprocess.Popen': ObjectType.PROCESS,
        'subprocess.run': ObjectType.PROCESS,
    }

    def __init__(self):
        self.object_types: Dict[str, ObjectType] = {}
        # Track Flask/Django request objects
        self.web_request_objects: Set[str] = set()

    def track_assignment(self, var_name: str, call_expr: CallExpression) -> None:
        """Track if assignment creates an I/O object"""
        qualified_name = call_expr.qualified_name
        func_name = call_expr.function_name

        # Check if this creates an I/O object
        for constructor, obj_type in self.IO_CONSTRUCTORS.items():
            if constructor in qualified_name or func_name == constructor.split('.')[-1]:
                self.object_types[var_name] = obj_type
                return

    def track_web_request_import(self, var_name: str, import_source: str) -> None:
        """
        Track Flask/Django request object imports.

        Examples:
        - from flask import request  → request is WEB_REQUEST
        - from django.http import HttpRequest → HttpRequest is WEB_REQUEST
        """
        if 'request' in import_source.lower():
            self.web_request_objects.add(var_name)

    def is_web_request_object(self, var_name: str) -> bool:
        """Check if variable is a web request object (Flask/Django)"""
        return var_name in self.web_request_objects

    def is_io_operation(self, var_name: str) -> Optional[ObjectType]:
        """
        Check if variable is an I/O object.

        If yes, ANY method call on it returns tainted data.
        This works for read(), readline(), recv(), .text, .json(), etc.
        WITHOUT hardcoding each method name!
        """
        # Check web request objects first
        if self.is_web_request_object(var_name):
            return self.WEB_REQUEST

        return self.object_types.get(var_name)

    def get_all_io_objects(self) -> Dict[str, ObjectType]:
        """Get all tracked I/O objects"""
        return self.object_types.copy()


class ModuleScopeDetector:
    """
    Module-level danger classification.

    Instead of listing every os.system, os.popen, os.exec, etc.,
    classify MODULES as dangerous. Then ANY call to that module = sink.
    """

    # Minimal list of dangerous modules
    DANGEROUS_MODULES = {
        # Command execution
        'os': {'category': 'command_exec', 'severity': 'high'},
        'subprocess': {'category': 'command_exec', 'severity': 'high'},
        'commands': {'category': 'command_exec', 'severity': 'medium'},
        'pty': {'category': 'command_exec', 'severity': 'medium'},

        # Serialization
        'pickle': {'category': 'deserialization', 'severity': 'high'},
        'marshal': {'category': 'deserialization', 'severity': 'high'},
        'shelve': {'category': 'deserialization', 'severity': 'medium'},

        # Unsafe YAML
        'yaml': {'category': 'deserialization', 'severity': 'medium'},  # Context-dependent
    }

    # Built-in dangerous functions (unavoidable small list)
    DANGEROUS_BUILTINS = {
        'eval', 'exec', 'compile', '__import__'
    }

    def is_dangerous_module_call(
        self,
        module_name: str,
        func_name: str
    ) -> Optional[Dict]:
        """
        Check if call is to dangerous module.

        Returns metadata if dangerous, None otherwise.
        """
        if module_name in self.DANGEROUS_MODULES:
            return self.DANGEROUS_MODULES[module_name]
        return None

    def is_dangerous_builtin(self, func_name: str) -> bool:
        """Check if function is dangerous built-in"""
        return func_name in self.DANGEROUS_BUILTINS


class ASTStructuralDetector:
    """
    Detect sources/sinks by AST structure, not function names.

    Examples:
    - sys.argv[1] → Detected by subscript on 'sys.argv' name
    - os.environ["KEY"] → Detected by subscript on 'os.environ'
    - No function name matching needed!
    """

    @staticmethod
    def is_argv_access(node: ASTNode) -> bool:
        """Detect sys.argv[index] by AST structure"""
        if node.type != 'subscript':
            return False

        value = node.child_by_field_name('value')
        if not value:
            return False

        # Check if it's sys.argv or os.environ
        text = value.text
        return 'sys.argv' in text or 'argv' == text

    @staticmethod
    def is_environ_access(node: ASTNode) -> bool:
        """Detect os.environ[key] or os.getenv() by structure"""
        if node.type == 'subscript':
            value = node.child_by_field_name('value')
            if value and 'environ' in value.text:
                return True

        if node.type == 'call':
            try:
                call_expr = CallExpression(node.node, node.source_code)
                if 'getenv' in call_expr.function_name:
                    return True
            except:
                pass

        return False

    @staticmethod
    def is_stdin_read(node: ASTNode) -> bool:
        """Detect sys.stdin.read*() operations"""
        if node.type == 'call':
            try:
                call_expr = CallExpression(node.node, node.source_code)
                qualified = call_expr.qualified_name
                if 'sys.stdin' in qualified or 'stdin.read' in qualified:
                    return True
            except:
                pass
        return False


class SemanticSourceDetector:
    """
    Semantic source detection using object tracking + AST patterns.

    Detects sources by WHAT THEY DO, not WHAT THEY'RE CALLED.
    """

    def __init__(self):
        self.object_tracker = IOObjectTracker()
        self.ast_detector = ASTStructuralDetector()

    def track_assignment(self, var_name: str, call_expr: CallExpression) -> None:
        """Track assignments that create I/O objects"""
        self.object_tracker.track_assignment(var_name, call_expr)

    def is_source(
        self,
        node: ASTNode,
        call_expr: Optional[CallExpression] = None
    ) -> Optional[tuple]:
        """
        Detect if node is a taint source.

        Returns: (source_description, confidence) or None
        """
        # AST structural detection (highest confidence)
        if self.ast_detector.is_argv_access(node):
            return ("Command line argument (sys.argv)", 0.95)

        if self.ast_detector.is_environ_access(node):
            return ("Environment variable", 0.95)

        if self.ast_detector.is_stdin_read(node):
            return ("Standard input", 0.95)

        # Check for web request attribute/method access
        # request.args.get(), request.cookies.get(), request.form['x'], etc.
        if node.type in ['call', 'attribute', 'subscript']:
            if self._is_web_request_access(node):
                return ("Web request data (Flask/Django)", 0.95)

        # I/O object method calls
        if call_expr:
            # Check if call is on an I/O object
            # e.g., file.read(), socket.recv(), response.text
            if hasattr(call_expr, 'object_name') and call_expr.object_name:
                obj_type = self.object_tracker.is_io_operation(call_expr.object_name)
                if obj_type:
                    return (f"{obj_type.value} read operation", 0.90)

            # Check if call itself creates tainted data
            func_name = call_expr.function_name.lower()

            # Built-in input functions
            if func_name in ['input', 'raw_input']:
                return ("User input function", 0.95)

        return None

    def _is_web_request_access(self, node: ASTNode) -> bool:
        """
        Detect access to web request object attributes/methods.

        Examples:
        - request.args.get('x')
        - request.cookies.get('x')
        - request.form['x']
        - request.json
        """
        # Get the base object name
        text = node.text

        # Check if 'request' appears in the expression
        if 'request' not in text:
            return False

        # Common patterns for web frameworks
        web_patterns = [
            'request.args', 'request.form', 'request.cookies',
            'request.json', 'request.data', 'request.values',
            'request.GET', 'request.POST',  # Django
        ]

        for pattern in web_patterns:
            if pattern in text:
                return True

        return False

    def get_tracked_objects(self) -> Dict[str, ObjectType]:
        """Get all tracked I/O objects"""
        return self.object_tracker.get_all_io_objects()


class SemanticSinkDetector:
    """
    Semantic sink detection using module classification.

    Instead of listing every dangerous function, classify modules.
    """

    def __init__(self):
        self.module_detector = ModuleScopeDetector()

    def is_sink(
        self,
        call_expr: CallExpression,
        module_context: Optional[str] = None
    ) -> Optional[tuple]:
        """
        Detect if call is a sink.

        Returns: (sink_category, severity, confidence) or None
        """
        func_name = call_expr.function_name
        qualified_name = call_expr.qualified_name

        # Check built-in dangerous functions
        if self.module_detector.is_dangerous_builtin(func_name):
            return ("code_evaluation", "critical", 0.95)

        # Check for file operations (path traversal risk)
        if func_name in ['open', 'file']:
            return ("path_traversal", "high", 0.90)

        # Check for pickle/marshal (deserialization)
        if func_name in ['loads', 'load'] and ('pickle' in qualified_name or 'marshal' in qualified_name):
            return ("deserialization", "critical", 0.95)

        # Extract module name from qualified name
        if '.' in qualified_name:
            parts = qualified_name.split('.')
            module = parts[0]

            # Check if module is dangerous
            module_info = self.module_detector.is_dangerous_module_call(module, func_name)
            if module_info:
                return (
                    module_info['category'],
                    module_info['severity'],
                    0.90  # High confidence for module-based detection
                )

        # Use module context if available
        if module_context:
            module_info = self.module_detector.is_dangerous_module_call(module_context, func_name)
            if module_info:
                return (
                    module_info['category'],
                    module_info['severity'],
                    0.85  # Slightly lower confidence from context
                )

        return None


class SemanticTaintDetector:
    """
    Combined semantic taint detector.

    Uses:
    1. Object tracking for sources (files, sockets, HTTP)
    2. Module classification for sinks (os.*, subprocess.*)
    3. AST structural patterns (sys.argv, os.environ)

    Dramatically reduces hardcoded lists while improving coverage.
    """

    def __init__(self):
        self.source_detector = SemanticSourceDetector()
        self.sink_detector = SemanticSinkDetector()

    def track_assignment(self, var_name: str, call_expr: CallExpression) -> None:
        """Track variable assignments for object tracking"""
        self.source_detector.track_assignment(var_name, call_expr)

    def is_source(self, node: ASTNode, call_expr: Optional[CallExpression] = None) -> Optional[tuple]:
        """Detect taint source"""
        return self.source_detector.is_source(node, call_expr)

    def is_sink(self, call_expr: CallExpression, module_context: Optional[str] = None) -> Optional[tuple]:
        """Detect taint sink"""
        return self.sink_detector.is_sink(call_expr, module_context)

    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        return {
            'tracked_io_objects': len(self.source_detector.get_tracked_objects()),
            'io_object_types': {
                str(k): str(v)
                for k, v in self.source_detector.get_tracked_objects().items()
            }
        }
