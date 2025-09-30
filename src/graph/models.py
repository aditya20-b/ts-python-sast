"""
Data models for call graph representation
"""

from typing import Dict, List, Set, Optional, Any, Union
from pydantic import BaseModel, Field
from enum import Enum


class NodeType(str, Enum):
    """Types of nodes in the call graph"""
    FUNCTION = "function"
    METHOD = "method"
    LAMBDA = "lambda"
    MODULE = "module"
    BUILTIN = "builtin"
    EXTERNAL = "external"
    UNRESOLVED = "unresolved"


class CallType(str, Enum):
    """Types of function calls"""
    DIRECT = "direct"          # Direct function call
    INDIRECT = "indirect"      # Through variable assignment
    DYNAMIC = "dynamic"        # Dynamic/runtime call
    RECURSIVE = "recursive"    # Self-recursive call


class SymbolInfo(BaseModel):
    """Information about a symbol (function/method)"""
    name: str = Field(..., description="Symbol name")
    qualified_name: str = Field(..., description="Fully qualified name")
    node_type: NodeType = Field(..., description="Type of node")
    file_path: str = Field(..., description="Source file path")
    start_line: int = Field(..., description="Start line number")
    start_column: int = Field(..., description="Start column number")
    end_line: int = Field(..., description="End line number")
    end_column: int = Field(..., description="End column number")
    parameters: List[str] = Field(default_factory=list, description="Parameter names")
    is_async: bool = Field(default=False, description="Is async function")
    is_generator: bool = Field(default=False, description="Is generator function")
    docstring: Optional[str] = Field(None, description="Function docstring")
    decorators: List[str] = Field(default_factory=list, description="Applied decorators")
    complexity: int = Field(default=1, description="Cyclomatic complexity estimate")


class CallEdge(BaseModel):
    """Represents a call relationship between two functions"""
    caller: str = Field(..., description="Caller function qualified name")
    callee: str = Field(..., description="Callee function qualified name")
    call_type: CallType = Field(..., description="Type of call")
    file_path: str = Field(..., description="File where call occurs")
    line: int = Field(..., description="Line number of call")
    column: int = Field(..., description="Column number of call")
    call_expression: str = Field(..., description="Original call expression text")
    is_conditional: bool = Field(default=False, description="Call is inside conditional")
    confidence: float = Field(default=1.0, description="Confidence in call resolution")


class CallGraph(BaseModel):
    """Complete call graph representation"""
    file_path: str = Field(..., description="Source file path")
    symbols: Dict[str, SymbolInfo] = Field(default_factory=dict, description="Symbol table")
    edges: List[CallEdge] = Field(default_factory=list, description="Call edges")
    entry_points: Set[str] = Field(default_factory=set, description="Entry point functions")
    reachable_nodes: Set[str] = Field(default_factory=set, description="Reachable functions")
    external_calls: Dict[str, int] = Field(default_factory=dict, description="External function call counts")
    unresolved_calls: List[str] = Field(default_factory=list, description="Unresolved call expressions")
    analysis_metadata: Dict[str, Any] = Field(default_factory=dict, description="Analysis metadata")

    class Config:
        """Pydantic configuration"""
        json_encoders = {
            set: list  # Convert sets to lists for JSON serialization
        }

    def get_callers(self, function_name: str) -> List[str]:
        """Get functions that call the specified function"""
        return [edge.caller for edge in self.edges if edge.callee == function_name]

    def get_callees(self, function_name: str) -> List[str]:
        """Get functions called by the specified function"""
        return [edge.callee for edge in self.edges if edge.caller == function_name]

    def get_call_count(self, caller: str, callee: str) -> int:
        """Get number of calls between two functions"""
        return len([e for e in self.edges if e.caller == caller and e.callee == callee])

    def is_reachable(self, function_name: str) -> bool:
        """Check if function is reachable from entry points"""
        return function_name in self.reachable_nodes

    def get_entry_points(self) -> List[str]:
        """Get list of entry point functions"""
        return list(self.entry_points)

    def get_leaf_functions(self) -> List[str]:
        """Get functions that don't call any other functions"""
        callers = {edge.caller for edge in self.edges}
        all_functions = set(self.symbols.keys())
        return list(all_functions - callers)

    def get_root_functions(self) -> List[str]:
        """Get functions that are never called by others"""
        callees = {edge.callee for edge in self.edges}
        all_functions = set(self.symbols.keys())
        return list(all_functions - callees)

    def get_recursive_functions(self) -> List[str]:
        """Get functions that call themselves (directly recursive)"""
        return [edge.caller for edge in self.edges
                if edge.caller == edge.callee and edge.call_type == CallType.RECURSIVE]

    def get_strongly_connected_components(self) -> List[List[str]]:
        """Get strongly connected components (mutual recursion groups)"""
        # Simple implementation - could be enhanced with Tarjan's algorithm
        components = []
        visited = set()

        def dfs(node: str, component: List[str]) -> None:
            if node in visited:
                return
            visited.add(node)
            component.append(node)

            for callee in self.get_callees(node):
                if callee in self.symbols:  # Only internal functions
                    dfs(callee, component)

        for symbol in self.symbols:
            if symbol not in visited:
                component = []
                dfs(symbol, component)
                if len(component) > 1 or any(self.get_call_count(symbol, symbol) > 0 for symbol in component):
                    components.append(component)

        return components


class GraphExportFormat(str, Enum):
    """Supported graph export formats"""
    DOT = "dot"
    JSON = "json"
    GRAPHML = "graphml"
    CYTOSCAPE = "cytoscape"


class GraphLayoutHint(str, Enum):
    """Graph layout hints for visualization"""
    HIERARCHICAL = "hierarchical"    # Top-down hierarchy
    FORCE_DIRECTED = "force_directed"  # Force-directed layout
    CIRCULAR = "circular"            # Circular layout
    TREE = "tree"                    # Tree layout


class GraphExportOptions(BaseModel):
    """Options for graph export"""
    format: GraphExportFormat = Field(..., description="Export format")
    include_external: bool = Field(default=False, description="Include external function calls")
    include_unresolved: bool = Field(default=False, description="Include unresolved calls")
    only_reachable: bool = Field(default=False, description="Only include reachable functions")
    layout_hint: GraphLayoutHint = Field(default=GraphLayoutHint.HIERARCHICAL, description="Layout hint")
    node_attributes: List[str] = Field(default_factory=list, description="Node attributes to include")
    edge_attributes: List[str] = Field(default_factory=list, description="Edge attributes to include")
    clustering: bool = Field(default=False, description="Group functions by file/module")


class ReachabilityAnalysis(BaseModel):
    """Results of reachability analysis"""
    entry_points: List[str] = Field(..., description="Entry point functions")
    reachable_functions: Set[str] = Field(..., description="Reachable function names")
    unreachable_functions: Set[str] = Field(..., description="Unreachable function names")
    call_chains: Dict[str, List[List[str]]] = Field(default_factory=dict, description="Call chains to each function")
    max_depth: int = Field(..., description="Maximum call depth from entry points")
    reachability_tree: Dict[str, List[str]] = Field(default_factory=dict, description="Reachability tree structure")

    class Config:
        """Pydantic configuration"""
        json_encoders = {
            set: list
        }

    def get_distance_to_entry(self, function_name: str) -> Optional[int]:
        """Get minimum distance from any entry point to the function"""
        if function_name in self.entry_points:
            return 0

        min_distance = float('inf')
        for entry_point, chains in self.call_chains.items():
            for chain in chains:
                if function_name in chain:
                    distance = chain.index(function_name)
                    min_distance = min(min_distance, distance)

        return int(min_distance) if min_distance != float('inf') else None

    def is_reachable_from(self, function_name: str, entry_point: str) -> bool:
        """Check if function is reachable from specific entry point"""
        chains = self.call_chains.get(entry_point, [])
        return any(function_name in chain for chain in chains)


class CallGraphStats(BaseModel):
    """Statistics about the call graph"""
    total_functions: int = Field(..., description="Total number of functions")
    total_calls: int = Field(..., description="Total number of call edges")
    entry_points: int = Field(..., description="Number of entry points")
    reachable_functions: int = Field(..., description="Number of reachable functions")
    unreachable_functions: int = Field(..., description="Number of unreachable functions")
    leaf_functions: int = Field(..., description="Functions that don't call others")
    root_functions: int = Field(..., description="Functions never called by others")
    recursive_functions: int = Field(..., description="Directly recursive functions")
    max_call_depth: int = Field(..., description="Maximum call depth")
    avg_calls_per_function: float = Field(..., description="Average calls per function")
    external_calls: int = Field(..., description="Calls to external functions")
    unresolved_calls: int = Field(..., description="Unresolved function calls")
    complexity_distribution: Dict[str, int] = Field(default_factory=dict, description="Complexity distribution")

    @classmethod
    def from_call_graph(cls, graph: CallGraph, reachability: Optional[ReachabilityAnalysis] = None) -> 'CallGraphStats':
        """Create statistics from call graph"""
        total_functions = len(graph.symbols)
        total_calls = len(graph.edges)
        leaf_functions = len(graph.get_leaf_functions())
        root_functions = len(graph.get_root_functions())
        recursive_functions = len(graph.get_recursive_functions())

        reachable_count = len(graph.reachable_nodes) if graph.reachable_nodes else 0
        unreachable_count = total_functions - reachable_count

        max_depth = reachability.max_depth if reachability else 0
        avg_calls = total_calls / max(total_functions, 1)

        # Complexity distribution
        complexity_dist = {}
        for symbol in graph.symbols.values():
            complexity_range = f"{(symbol.complexity // 5) * 5}-{(symbol.complexity // 5 + 1) * 5}"
            complexity_dist[complexity_range] = complexity_dist.get(complexity_range, 0) + 1

        return cls(
            total_functions=total_functions,
            total_calls=total_calls,
            entry_points=len(graph.entry_points),
            reachable_functions=reachable_count,
            unreachable_functions=unreachable_count,
            leaf_functions=leaf_functions,
            root_functions=root_functions,
            recursive_functions=recursive_functions,
            max_call_depth=max_depth,
            avg_calls_per_function=round(avg_calls, 2),
            external_calls=sum(graph.external_calls.values()),
            unresolved_calls=len(graph.unresolved_calls),
            complexity_distribution=complexity_dist
        )