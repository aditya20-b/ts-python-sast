"""
Data models for taint analysis
"""

from typing import List, Set, Dict, Optional, Any
from pydantic import BaseModel, Field
from enum import Enum


class TaintLabel(str, Enum):
    """Types of taint labels"""
    USER = "user"              # User input
    ENV = "env"                # Environment variables
    FILE = "file"              # File reads
    NETWORK = "network"        # Network data
    DATABASE = "database"      # Database queries
    UNKNOWN = "unknown"        # Unknown source


class TaintStatus(str, Enum):
    """Taint status of a value"""
    UNTAINTED = "untainted"
    TAINTED = "tainted"
    SANITIZED = "sanitized"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Types of taint sources"""
    USER_INPUT = "user_input"           # input(), raw_input()
    FLASK_REQUEST = "flask_request"     # flask.request.*
    DJANGO_REQUEST = "django_request"   # request.GET, request.POST
    FASTAPI_REQUEST = "fastapi_request" # FastAPI params
    SYS_ARGV = "sys_argv"               # sys.argv
    ENV_VAR = "env_var"                 # os.environ, os.getenv
    FILE_READ = "file_read"             # open().read()
    NETWORK_READ = "network_read"       # socket.recv, requests.get
    DATABASE_READ = "database_read"     # cursor.fetchone/fetchall


class SinkType(str, Enum):
    """Types of taint sinks"""
    COMMAND_EXEC = "command_exec"       # subprocess, os.system
    CODE_EVAL = "code_eval"             # eval, exec, compile
    SQL_EXEC = "sql_exec"               # cursor.execute
    FILE_WRITE = "file_write"           # open().write()
    TEMPLATE_RENDER = "template_render" # Jinja2, Django templates
    HTTP_REQUEST = "http_request"       # requests.*, urllib
    SERIALIZATION = "serialization"     # pickle.dump, json.dump
    LOG_OUTPUT = "log_output"           # logging.*, print (PII leak)
    PATH_TRAVERSAL = "path_traversal"   # file path operations


class SanitizerType(str, Enum):
    """Types of sanitizers"""
    SHELL_ESCAPE = "shell_escape"       # shlex.quote
    SQL_PARAMETERIZE = "sql_parameterize" # Parameterized queries
    HTML_ESCAPE = "html_escape"         # html.escape, markupsafe
    URL_ENCODE = "url_encode"           # urllib.parse.quote
    PATH_NORMALIZE = "path_normalize"   # os.path.normpath, Path.resolve
    TYPE_CAST = "type_cast"             # int(), float() - safe casts
    REGEX_VALIDATE = "regex_validate"   # re.match with validation
    ALLOWLIST_CHECK = "allowlist_check" # Checking against allowlist


class TaintSource(BaseModel):
    """Definition of a taint source"""
    name: str = Field(..., description="Source name (e.g., 'input')")
    qualified_name: Optional[str] = Field(None, description="Fully qualified name")
    source_type: SourceType = Field(..., description="Type of source")
    taint_label: TaintLabel = Field(..., description="Taint label to apply")
    patterns: List[str] = Field(default_factory=list, description="Matching patterns")
    confidence: float = Field(default=1.0, description="Confidence this is a source")


class TaintSink(BaseModel):
    """Definition of a taint sink"""
    name: str = Field(..., description="Sink name (e.g., 'os.system')")
    qualified_name: Optional[str] = Field(None, description="Fully qualified name")
    sink_type: SinkType = Field(..., description="Type of sink")
    severity: str = Field(..., description="Severity if tainted data reaches sink")
    patterns: List[str] = Field(default_factory=list, description="Matching patterns")
    vulnerable_params: List[int] = Field(default_factory=list, description="Which parameters are vulnerable (0-indexed)")


class Sanitizer(BaseModel):
    """Definition of a sanitizer function"""
    name: str = Field(..., description="Sanitizer name")
    qualified_name: Optional[str] = Field(None, description="Fully qualified name")
    sanitizer_type: SanitizerType = Field(..., description="Type of sanitizer")
    removes_labels: List[TaintLabel] = Field(default_factory=list, description="Which taint labels it removes")
    patterns: List[str] = Field(default_factory=list, description="Matching patterns")


class TaintedValue(BaseModel):
    """Represents a tainted value in the program"""
    variable_name: str = Field(..., description="Variable name")
    taint_status: TaintStatus = Field(..., description="Taint status")
    taint_labels: Set[TaintLabel] = Field(default_factory=set, description="Applied taint labels")
    source_location: Optional[str] = Field(None, description="Where value was tainted")
    source_line: Optional[int] = Field(None, description="Line number of source")

    class Config:
        json_encoders = {
            set: list
        }


class TaintFlowEdge(BaseModel):
    """Represents a taint flow between two program points"""
    from_var: str = Field(..., description="Source variable")
    to_var: str = Field(..., description="Destination variable")
    operation: str = Field(..., description="Operation that caused flow")
    location: str = Field(..., description="Code location")
    line: int = Field(..., description="Line number")
    preserves_taint: bool = Field(default=True, description="Whether taint is preserved")
    sanitizer_applied: Optional[str] = Field(None, description="Sanitizer applied, if any")


class TaintPath(BaseModel):
    """Complete path from source to sink"""
    source: str = Field(..., description="Source variable/function")
    source_type: SourceType = Field(..., description="Type of source")
    source_location: str = Field(..., description="Source location")
    source_line: int = Field(..., description="Source line number")

    sink: str = Field(..., description="Sink function")
    sink_type: SinkType = Field(..., description="Type of sink")
    sink_location: str = Field(..., description="Sink location")
    sink_line: int = Field(..., description="Sink line number")

    taint_labels: Set[TaintLabel] = Field(..., description="Taint labels involved")
    path_edges: List[TaintFlowEdge] = Field(..., description="Flow edges in path")

    is_sanitized: bool = Field(default=False, description="Whether path is sanitized")
    sanitizers: List[str] = Field(default_factory=list, description="Sanitizers encountered")

    severity: str = Field(..., description="Severity of this taint path")
    confidence: float = Field(default=1.0, description="Confidence in this path")

    class Config:
        json_encoders = {
            set: list
        }

    @property
    def path_length(self) -> int:
        """Get length of taint path"""
        return len(self.path_edges)

    @property
    def variables_involved(self) -> List[str]:
        """Get all variables involved in path"""
        vars_set = {self.source}
        for edge in self.path_edges:
            vars_set.add(edge.from_var)
            vars_set.add(edge.to_var)
        return list(vars_set)


class TaintAnalysisResult(BaseModel):
    """Results of taint analysis"""
    file_path: str = Field(..., description="Analyzed file path")
    taint_paths: List[TaintPath] = Field(..., description="Detected taint paths")
    sources_found: int = Field(..., description="Number of sources found")
    sinks_found: int = Field(..., description="Number of sinks found")
    sanitizers_found: int = Field(..., description="Number of sanitizers found")
    analysis_time_ms: float = Field(..., description="Analysis time in milliseconds")
    errors: Optional[List[str]] = Field(None, description="Analysis errors")

    @property
    def vulnerable_paths_count(self) -> int:
        """Count of unsanitized vulnerable paths"""
        return len([p for p in self.taint_paths if not p.is_sanitized])

    @property
    def sanitized_paths_count(self) -> int:
        """Count of sanitized paths"""
        return len([p for p in self.taint_paths if p.is_sanitized])

    def get_paths_by_severity(self) -> Dict[str, List[TaintPath]]:
        """Group paths by severity"""
        paths_by_severity = {}
        for path in self.taint_paths:
            if path.severity not in paths_by_severity:
                paths_by_severity[path.severity] = []
            paths_by_severity[path.severity].append(path)
        return paths_by_severity

    def get_paths_by_sink_type(self) -> Dict[SinkType, List[TaintPath]]:
        """Group paths by sink type"""
        paths_by_sink = {}
        for path in self.taint_paths:
            if path.sink_type not in paths_by_sink:
                paths_by_sink[path.sink_type] = []
            paths_by_sink[path.sink_type].append(path)
        return paths_by_sink


class TaintConfig(BaseModel):
    """Configuration for taint analysis"""
    sources: List[TaintSource] = Field(default_factory=list, description="Configured sources")
    sinks: List[TaintSink] = Field(default_factory=list, description="Configured sinks")
    sanitizers: List[Sanitizer] = Field(default_factory=list, description="Configured sanitizers")

    # Analysis options
    max_path_length: int = Field(default=20, description="Maximum path length to track")
    track_containers: bool = Field(default=True, description="Track taint through containers")
    inter_procedural: bool = Field(default=False, description="Enable inter-procedural analysis")
    confidence_threshold: float = Field(default=0.5, description="Minimum confidence for reporting")

    def add_default_sources(self) -> None:
        """Add default Python taint sources"""
        defaults = [
            TaintSource(name="input", source_type=SourceType.USER_INPUT, taint_label=TaintLabel.USER),
            TaintSource(name="raw_input", source_type=SourceType.USER_INPUT, taint_label=TaintLabel.USER),
            TaintSource(name="sys.argv", qualified_name="sys.argv", source_type=SourceType.SYS_ARGV, taint_label=TaintLabel.USER),
            TaintSource(name="os.environ", qualified_name="os.environ", source_type=SourceType.ENV_VAR, taint_label=TaintLabel.ENV),
            TaintSource(name="os.getenv", qualified_name="os.getenv", source_type=SourceType.ENV_VAR, taint_label=TaintLabel.ENV),
            TaintSource(name="request.args", qualified_name="flask.request.args", source_type=SourceType.FLASK_REQUEST, taint_label=TaintLabel.USER),
            TaintSource(name="request.form", qualified_name="flask.request.form", source_type=SourceType.FLASK_REQUEST, taint_label=TaintLabel.USER),
            TaintSource(name="request.json", qualified_name="flask.request.json", source_type=SourceType.FLASK_REQUEST, taint_label=TaintLabel.USER),
        ]
        self.sources.extend(defaults)

    def add_default_sinks(self) -> None:
        """Add default Python taint sinks"""
        defaults = [
            TaintSink(name="os.system", qualified_name="os.system", sink_type=SinkType.COMMAND_EXEC, severity="high"),
            TaintSink(name="subprocess.run", qualified_name="subprocess.run", sink_type=SinkType.COMMAND_EXEC, severity="high"),
            TaintSink(name="subprocess.call", qualified_name="subprocess.call", sink_type=SinkType.COMMAND_EXEC, severity="high"),
            TaintSink(name="subprocess.Popen", qualified_name="subprocess.Popen", sink_type=SinkType.COMMAND_EXEC, severity="high"),
            TaintSink(name="eval", sink_type=SinkType.CODE_EVAL, severity="critical"),
            TaintSink(name="exec", sink_type=SinkType.CODE_EVAL, severity="critical"),
            TaintSink(name="compile", sink_type=SinkType.CODE_EVAL, severity="high"),
            TaintSink(name="cursor.execute", sink_type=SinkType.SQL_EXEC, severity="high", vulnerable_params=[0]),
        ]
        self.sinks.extend(defaults)

    def add_default_sanitizers(self) -> None:
        """Add default Python sanitizers"""
        defaults = [
            Sanitizer(
                name="shlex.quote",
                qualified_name="shlex.quote",
                sanitizer_type=SanitizerType.SHELL_ESCAPE,
                removes_labels=[TaintLabel.USER, TaintLabel.FILE]
            ),
            Sanitizer(
                name="html.escape",
                qualified_name="html.escape",
                sanitizer_type=SanitizerType.HTML_ESCAPE,
                removes_labels=[TaintLabel.USER]
            ),
            Sanitizer(
                name="urllib.parse.quote",
                qualified_name="urllib.parse.quote",
                sanitizer_type=SanitizerType.URL_ENCODE,
                removes_labels=[TaintLabel.USER]
            ),
            Sanitizer(
                name="int",
                sanitizer_type=SanitizerType.TYPE_CAST,
                removes_labels=[TaintLabel.USER]
            ),
            Sanitizer(
                name="float",
                sanitizer_type=SanitizerType.TYPE_CAST,
                removes_labels=[TaintLabel.USER]
            ),
        ]
        self.sanitizers.extend(defaults)