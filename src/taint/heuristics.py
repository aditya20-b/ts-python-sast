"""
Heuristic-based detection for taint sources, sinks, and sanitizers
Uses pattern matching to dynamically identify security-relevant functions
"""

from typing import Optional, Set, List
from enum import Enum
from .models import SinkType, SourceType, TaintLabel


class HeuristicConfidence(Enum):
    """Confidence level for heuristic detection"""
    VERY_HIGH = 0.95  # Exact match from known list
    HIGH = 0.85       # Module + semantic pattern match
    MEDIUM = 0.70     # Semantic pattern only
    LOW = 0.50        # Weak pattern match


class DangerousModuleTaxonomy:
    """Classification of Python modules by security risk"""

    # Command execution modules
    COMMAND_EXECUTION = {
        'os', 'subprocess', 'commands', 'pty', 'platform',
        'popen2', 'distutils.spawn'
    }

    # Code evaluation modules
    CODE_EVALUATION = {
        'builtins', 'importlib', 'imp', '__builtin__', 'code'
    }

    # Database/SQL modules
    SQL_DATABASE = {
        'sqlite3', 'psycopg2', 'MySQLdb', 'pymysql', 'mysql',
        'sqlalchemy', 'django.db', 'peewee', 'pymongo'
    }

    # Serialization modules
    SERIALIZATION = {
        'pickle', 'marshal', 'shelve', 'dill', 'jsonpickle',
        'yaml'  # if using unsafe loader
    }

    # Network modules
    NETWORK = {
        'socket', 'urllib', 'urllib2', 'urllib3', 'requests',
        'httplib', 'http.client', 'aiohttp'
    }

    # File I/O modules
    FILE_IO = {
        'io', 'pathlib', 'shutil', 'tempfile'
    }

    # Web framework modules (sources)
    WEB_FRAMEWORKS = {
        'flask', 'django', 'fastapi', 'tornado', 'bottle',
        'pyramid', 'cherrypy', 'web', 'starlette'
    }

    # Logging modules (potential PII leaks)
    LOGGING = {
        'logging', 'syslog', 'warnings'
    }

    # Template engines
    TEMPLATE_ENGINES = {
        'jinja2', 'mako', 'cheetah', 'django.template'
    }

    @classmethod
    def get_all_dangerous_modules(cls) -> Set[str]:
        """Get all dangerous modules"""
        all_modules = set()
        for attr_name in dir(cls):
            attr = getattr(cls, attr_name)
            if isinstance(attr, set):
                all_modules.update(attr)
        return all_modules

    @classmethod
    def classify_module(cls, module_name: str) -> List[str]:
        """Classify a module by its security risk categories"""
        categories = []

        # Check each category
        if any(module_name.startswith(m) for m in cls.COMMAND_EXECUTION):
            categories.append('command_execution')
        if any(module_name.startswith(m) for m in cls.CODE_EVALUATION):
            categories.append('code_evaluation')
        if any(module_name.startswith(m) for m in cls.SQL_DATABASE):
            categories.append('sql_database')
        if any(module_name.startswith(m) for m in cls.SERIALIZATION):
            categories.append('serialization')
        if any(module_name.startswith(m) for m in cls.NETWORK):
            categories.append('network')
        if any(module_name.startswith(m) for m in cls.WEB_FRAMEWORKS):
            categories.append('web_framework')
        if any(module_name.startswith(m) for m in cls.TEMPLATE_ENGINES):
            categories.append('template_engine')

        return categories


class HeuristicSinkDetector:
    """Detect sinks using heuristic patterns"""

    # Command execution patterns
    COMMAND_EXEC_PATTERNS = {
        'exec', 'run', 'call', 'system', 'shell', 'popen', 'spawn',
        'command', 'cmd', 'process', 'invoke'
    }

    # Code evaluation patterns
    CODE_EVAL_PATTERNS = {
        'eval', 'exec', 'compile', 'import', 'load'
    }

    # SQL execution patterns
    SQL_EXEC_PATTERNS = {
        'execute', 'query', 'sql', 'select', 'insert', 'update',
        'delete', 'drop', 'create', 'alter', 'cursor'
    }

    # File write patterns
    FILE_WRITE_PATTERNS = {
        'write', 'writelines', 'dump', 'save', 'store'
    }

    # Network request patterns
    NETWORK_PATTERNS = {
        'send', 'sendall', 'request', 'get', 'post', 'put',
        'fetch', 'urlopen', 'connect'
    }

    # Template rendering patterns
    TEMPLATE_PATTERNS = {
        'render', 'template', 'format_string', 'substitute'
    }

    # Serialization patterns
    SERIALIZATION_PATTERNS = {
        'loads', 'load', 'unpickle', 'deserialize', 'unmarshal'
    }

    @classmethod
    def detect_sink_type(
        cls,
        function_name: str,
        qualified_name: str,
        module_context: Optional[str] = None
    ) -> Optional[tuple]:
        """
        Detect if a function is a sink using heuristics

        Returns:
            Optional[tuple]: (SinkType, severity, confidence) or None
        """
        func_lower = function_name.lower()
        qual_lower = qualified_name.lower()

        # Check module context first for higher confidence
        if module_context:
            module_categories = DangerousModuleTaxonomy.classify_module(module_context)

            # Command execution
            if 'command_execution' in module_categories:
                if any(p in func_lower for p in cls.COMMAND_EXEC_PATTERNS):
                    return (SinkType.COMMAND_EXEC, 'high', HeuristicConfidence.HIGH.value)

            # Code evaluation
            if 'code_evaluation' in module_categories:
                if any(p in func_lower for p in cls.CODE_EVAL_PATTERNS):
                    return (SinkType.CODE_EVAL, 'critical', HeuristicConfidence.HIGH.value)

            # SQL
            if 'sql_database' in module_categories:
                if any(p in func_lower for p in cls.SQL_EXEC_PATTERNS):
                    return (SinkType.SQL_EXEC, 'high', HeuristicConfidence.HIGH.value)

            # Serialization
            if 'serialization' in module_categories:
                if any(p in func_lower for p in cls.SERIALIZATION_PATTERNS):
                    return (SinkType.SERIALIZATION, 'high', HeuristicConfidence.HIGH.value)

            # Templates
            if 'template_engine' in module_categories:
                if any(p in func_lower for p in cls.TEMPLATE_PATTERNS):
                    return (SinkType.TEMPLATE_RENDER, 'high', HeuristicConfidence.HIGH.value)

        # Check patterns without module context (lower confidence)

        # Command execution (based on name alone)
        if any(p in func_lower for p in cls.COMMAND_EXEC_PATTERNS):
            # Additional check: avoid false positives like "execute_query"
            if any(sql_p in func_lower for sql_p in cls.SQL_EXEC_PATTERNS):
                return (SinkType.SQL_EXEC, 'high', HeuristicConfidence.MEDIUM.value)
            return (SinkType.COMMAND_EXEC, 'high', HeuristicConfidence.MEDIUM.value)

        # Code evaluation
        if any(p in func_lower for p in cls.CODE_EVAL_PATTERNS):
            return (SinkType.CODE_EVAL, 'critical', HeuristicConfidence.MEDIUM.value)

        # SQL execution
        if any(p in func_lower for p in cls.SQL_EXEC_PATTERNS):
            return (SinkType.SQL_EXEC, 'high', HeuristicConfidence.MEDIUM.value)

        # File write
        if any(p in func_lower for p in cls.FILE_WRITE_PATTERNS):
            return (SinkType.FILE_WRITE, 'medium', HeuristicConfidence.MEDIUM.value)

        # Network
        if any(p in func_lower for p in cls.NETWORK_PATTERNS):
            return (SinkType.HTTP_REQUEST, 'medium', HeuristicConfidence.LOW.value)

        # Template
        if any(p in func_lower for p in cls.TEMPLATE_PATTERNS):
            return (SinkType.TEMPLATE_RENDER, 'medium', HeuristicConfidence.LOW.value)

        # Serialization
        if any(p in func_lower for p in cls.SERIALIZATION_PATTERNS):
            return (SinkType.SERIALIZATION, 'high', HeuristicConfidence.MEDIUM.value)

        return None


class HeuristicSourceDetector:
    """Detect sources using heuristic patterns"""

    # User input patterns
    USER_INPUT_PATTERNS = {
        'input', 'raw_input', 'stdin', 'read_input', 'get_input'
    }

    # Command line argument patterns
    CLI_ARG_PATTERNS = {
        'argv', 'args', 'arguments', 'sys.argv', 'argparse'
    }

    # Environment variable patterns
    ENV_VAR_PATTERNS = {
        'environ', 'getenv', 'env', 'environment'
    }

    # Web request patterns
    WEB_REQUEST_PATTERNS = {
        'request', 'params', 'form', 'json', 'data', 'body',
        'query', 'args', 'values', 'cookies', 'headers'
    }

    # File read patterns
    FILE_READ_PATTERNS = {
        'read', 'readline', 'readlines', 'load', 'open'
    }

    # Network receive patterns
    NETWORK_RECV_PATTERNS = {
        'recv', 'recvfrom', 'receive', 'get', 'fetch', 'download'
    }

    @classmethod
    def detect_source_type(
        cls,
        function_name: str,
        qualified_name: str,
        module_context: Optional[str] = None
    ) -> Optional[tuple]:
        """
        Detect if a function is a source using heuristics

        Returns:
            Optional[tuple]: (SourceType, TaintLabel, confidence) or None
        """
        func_lower = function_name.lower()
        qual_lower = qualified_name.lower()

        # Check module context first
        if module_context:
            module_categories = DangerousModuleTaxonomy.classify_module(module_context)

            # Web framework requests
            if 'web_framework' in module_categories:
                if any(p in qual_lower for p in cls.WEB_REQUEST_PATTERNS):
                    return (SourceType.FLASK_REQUEST, TaintLabel.USER, HeuristicConfidence.HIGH.value)

            # Network modules
            if 'network' in module_categories:
                if any(p in func_lower for p in cls.NETWORK_RECV_PATTERNS):
                    return (SourceType.NETWORK_READ, TaintLabel.NETWORK, HeuristicConfidence.HIGH.value)

        # Pattern matching without module context

        # User input
        if any(p in func_lower for p in cls.USER_INPUT_PATTERNS):
            return (SourceType.USER_INPUT, TaintLabel.USER, HeuristicConfidence.MEDIUM.value)

        # Command line args
        if any(p in qual_lower for p in cls.CLI_ARG_PATTERNS):
            return (SourceType.SYS_ARGV, TaintLabel.USER, HeuristicConfidence.MEDIUM.value)

        # Environment variables
        if any(p in func_lower for p in cls.ENV_VAR_PATTERNS):
            return (SourceType.ENV_VAR, TaintLabel.ENV, HeuristicConfidence.MEDIUM.value)

        # Web requests
        if any(p in qual_lower for p in cls.WEB_REQUEST_PATTERNS):
            return (SourceType.FLASK_REQUEST, TaintLabel.USER, HeuristicConfidence.MEDIUM.value)

        # File reads
        if any(p in func_lower for p in cls.FILE_READ_PATTERNS):
            return (SourceType.FILE_READ, TaintLabel.FILE, HeuristicConfidence.LOW.value)

        # Network
        if any(p in func_lower for p in cls.NETWORK_RECV_PATTERNS):
            return (SourceType.NETWORK_READ, TaintLabel.NETWORK, HeuristicConfidence.LOW.value)

        return None


class HeuristicSanitizerDetector:
    """Detect sanitizers using heuristic patterns"""

    # Escape/encoding patterns
    ESCAPE_PATTERNS = {
        'escape', 'quote', 'encode', 'urlencode', 'htmlescape',
        'sanitize', 'clean', 'safe'
    }

    # Validation patterns
    VALIDATION_PATTERNS = {
        'validate', 'check', 'verify', 'is_valid', 'is_safe',
        'assert', 'ensure', 'filter'
    }

    # Normalization patterns
    NORMALIZATION_PATTERNS = {
        'normalize', 'normpath', 'abspath', 'realpath', 'canonical'
    }

    # Type conversion patterns (for command injection)
    TYPE_CONVERSION_PATTERNS = {
        'int', 'float', 'str', 'bool', 'to_int', 'to_number',
        'parse_int', 'parse_float'
    }

    @classmethod
    def is_sanitizer(
        cls,
        function_name: str,
        qualified_name: str,
        module_context: Optional[str] = None
    ) -> Optional[tuple]:
        """
        Detect if a function is a sanitizer

        Returns:
            Optional[tuple]: (sanitizer_type, removes_labels, confidence) or None
        """
        func_lower = function_name.lower()
        qual_lower = qualified_name.lower()

        # Escape/encoding functions
        if any(p in func_lower for p in cls.ESCAPE_PATTERNS):
            # Determine what taint it removes based on function name
            if any(x in func_lower for x in ['html', 'xss']):
                return ('html_escape', [TaintLabel.USER], HeuristicConfidence.MEDIUM.value)
            elif any(x in func_lower for x in ['shell', 'quote', 'cmd']):
                return ('shell_escape', [TaintLabel.USER, TaintLabel.ENV], HeuristicConfidence.MEDIUM.value)
            elif any(x in func_lower for x in ['url', 'uri']):
                return ('url_encode', [TaintLabel.USER], HeuristicConfidence.MEDIUM.value)
            elif any(x in func_lower for x in ['sql', 'db']):
                return ('sql_escape', [TaintLabel.USER], HeuristicConfidence.MEDIUM.value)
            else:
                return ('generic_escape', [TaintLabel.USER], HeuristicConfidence.LOW.value)

        # Validation functions
        if any(p in func_lower for p in cls.VALIDATION_PATTERNS):
            return ('validation', [TaintLabel.USER], HeuristicConfidence.LOW.value)

        # Normalization
        if any(p in func_lower for p in cls.NORMALIZATION_PATTERNS):
            return ('normalization', [TaintLabel.USER], HeuristicConfidence.LOW.value)

        # Type conversions (removes command injection risk)
        if any(p in func_lower for p in cls.TYPE_CONVERSION_PATTERNS):
            return ('type_conversion', [TaintLabel.USER], HeuristicConfidence.MEDIUM.value)

        return None
