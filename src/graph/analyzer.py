"""
Reachability analysis for call graphs
"""

from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict, deque

from .models import CallGraph, ReachabilityAnalysis, CallGraphStats


class ReachabilityAnalyzer:
    """Analyzes function reachability from entry points"""

    def __init__(self, call_graph: CallGraph):
        self.call_graph = call_graph
        self._adjacency_list: Optional[Dict[str, List[str]]] = None
        self._reverse_adjacency_list: Optional[Dict[str, List[str]]] = None

    def analyze(self, entry_points: Optional[List[str]] = None,
                max_depth: int = 100) -> ReachabilityAnalysis:
        """Perform reachability analysis from specified entry points"""

        # Use provided entry points or discover them from call graph
        if entry_points is None:
            entry_points = list(self.call_graph.entry_points)

        if not entry_points:
            # If no entry points specified, use all root functions
            entry_points = self.call_graph.get_root_functions()

        # Build adjacency lists for efficient traversal
        self._build_adjacency_lists()

        # Perform reachability analysis
        reachable_functions = set()
        call_chains = {}
        reachability_tree = defaultdict(list)
        actual_max_depth = 0

        for entry_point in entry_points:
            if entry_point in self.call_graph.symbols:
                chains, depth = self._find_reachable_from(entry_point, max_depth)
                call_chains[entry_point] = chains
                actual_max_depth = max(actual_max_depth, depth)

                # Build reachability tree
                for chain in chains:
                    for i, func in enumerate(chain[:-1]):
                        if chain[i + 1] not in reachability_tree[func]:
                            reachability_tree[func].append(chain[i + 1])

                # Add all functions in chains to reachable set
                for chain in chains:
                    reachable_functions.update(chain)

        # Update call graph with reachable functions
        self.call_graph.reachable_nodes = reachable_functions

        # Find unreachable functions
        all_functions = set(self.call_graph.symbols.keys())
        unreachable_functions = all_functions - reachable_functions

        return ReachabilityAnalysis(
            entry_points=entry_points,
            reachable_functions=reachable_functions,
            unreachable_functions=unreachable_functions,
            call_chains=call_chains,
            max_depth=actual_max_depth,
            reachability_tree=dict(reachability_tree)
        )

    def _build_adjacency_lists(self) -> None:
        """Build adjacency lists for efficient graph traversal"""
        self._adjacency_list = defaultdict(list)
        self._reverse_adjacency_list = defaultdict(list)

        for edge in self.call_graph.edges:
            # Only include internal function calls (both caller and callee in symbols)
            if (edge.caller in self.call_graph.symbols and
                edge.callee in self.call_graph.symbols):
                self._adjacency_list[edge.caller].append(edge.callee)
                self._reverse_adjacency_list[edge.callee].append(edge.caller)

    def _find_reachable_from(self, entry_point: str, max_depth: int) -> Tuple[List[List[str]], int]:
        """Find all functions reachable from an entry point using BFS"""
        if not self._adjacency_list:
            return [], 0

        visited = set()
        call_chains = []
        max_depth_reached = 0

        # BFS to find all reachable functions and their call chains
        queue = deque([(entry_point, [entry_point], 0)])  # (current_func, path, depth)

        while queue:
            current_func, path, depth = queue.popleft()

            if depth > max_depth:
                continue

            max_depth_reached = max(max_depth_reached, depth)

            # Add current path to call chains if it's longer than just the entry point
            if len(path) > 1 or current_func == entry_point:
                call_chains.append(path.copy())

            # Explore neighbors
            for neighbor in self._adjacency_list.get(current_func, []):
                new_path = path + [neighbor]

                # Avoid infinite recursion by limiting revisits
                if neighbor not in visited or depth < max_depth // 2:
                    queue.append((neighbor, new_path, depth + 1))
                    visited.add(neighbor)

        # Remove duplicate chains and sort by length
        unique_chains = []
        seen_chains = set()

        for chain in call_chains:
            chain_key = tuple(chain)
            if chain_key not in seen_chains:
                unique_chains.append(chain)
                seen_chains.add(chain_key)

        # Sort chains by length (shorter first)
        unique_chains.sort(key=len)

        return unique_chains, max_depth_reached

    def find_shortest_path(self, from_func: str, to_func: str) -> Optional[List[str]]:
        """Find shortest call path between two functions"""
        if not self._adjacency_list or from_func not in self._adjacency_list:
            return None

        # BFS to find shortest path
        queue = deque([(from_func, [from_func])])
        visited = {from_func}

        while queue:
            current_func, path = queue.popleft()

            if current_func == to_func:
                return path

            for neighbor in self._adjacency_list.get(current_func, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return None

    def find_all_paths(self, from_func: str, to_func: str, max_paths: int = 10) -> List[List[str]]:
        """Find multiple paths between two functions"""
        if not self._adjacency_list:
            return []

        all_paths = []

        def dfs_paths(current: str, target: str, path: List[str], visited: Set[str]) -> None:
            if len(all_paths) >= max_paths:
                return

            if current == target:
                all_paths.append(path.copy())
                return

            if len(path) > 10:  # Prevent very long paths
                return

            for neighbor in self._adjacency_list.get(current, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    path.append(neighbor)
                    dfs_paths(neighbor, target, path, visited)
                    path.pop()
                    visited.remove(neighbor)

        dfs_paths(from_func, to_func, [from_func], {from_func})
        return all_paths

    def find_cycles(self) -> List[List[str]]:
        """Find all cycles in the call graph"""
        if not self._adjacency_list:
            return []

        cycles = []
        visited = set()
        rec_stack = set()

        def dfs_cycles(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in self._adjacency_list.get(node, []):
                if neighbor not in visited:
                    dfs_cycles(neighbor, path)
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor)
                    cycle = path[cycle_start:] + [neighbor]
                    if len(cycle) > 2:  # Only include non-trivial cycles
                        cycles.append(cycle)

            path.pop()
            rec_stack.remove(node)

        for func in self.call_graph.symbols:
            if func not in visited:
                dfs_cycles(func, [])

        return cycles

    def analyze_centrality(self) -> Dict[str, Dict[str, float]]:
        """Calculate centrality measures for functions"""
        if not self._adjacency_list:
            return {}

        functions = list(self.call_graph.symbols.keys())
        centrality = {}

        for func in functions:
            # In-degree centrality (how many functions call this one)
            in_degree = len(self._reverse_adjacency_list.get(func, []))

            # Out-degree centrality (how many functions this one calls)
            out_degree = len(self._adjacency_list.get(func, []))

            # Betweenness centrality (simplified approximation)
            betweenness = self._estimate_betweenness(func)

            centrality[func] = {
                'in_degree': in_degree,
                'out_degree': out_degree,
                'total_degree': in_degree + out_degree,
                'betweenness': betweenness
            }

        return centrality

    def _estimate_betweenness(self, func: str) -> float:
        """Estimate betweenness centrality for a function"""
        # Simplified betweenness calculation
        # Count how many shortest paths pass through this function
        betweenness_score = 0.0
        functions = list(self.call_graph.symbols.keys())

        for source in functions[:10]:  # Limit for performance
            for target in functions[:10]:
                if source != target and source != func and target != func:
                    path = self.find_shortest_path(source, target)
                    if path and func in path:
                        betweenness_score += 1.0

        # Normalize by possible pairs
        max_pairs = min(10, len(functions)) ** 2
        return betweenness_score / max(max_pairs, 1)

    def generate_statistics(self) -> CallGraphStats:
        """Generate comprehensive statistics about the call graph"""
        reachability = self.analyze()
        return CallGraphStats.from_call_graph(self.call_graph, reachability)

    def find_dead_code(self) -> List[str]:
        """Find functions that are never called (potential dead code)"""
        reachability = self.analyze()
        return list(reachability.unreachable_functions)

    def find_critical_functions(self, top_k: int = 5) -> List[Tuple[str, Dict[str, float]]]:
        """Find most critical functions based on centrality measures"""
        centrality = self.analyze_centrality()

        # Sort by total degree (in + out degree)
        critical_functions = sorted(
            centrality.items(),
            key=lambda x: x[1]['total_degree'] + x[1]['betweenness'],
            reverse=True
        )

        return critical_functions[:top_k]

    def estimate_impact(self, function_name: str) -> Dict[str, Any]:
        """Estimate the impact of removing or modifying a function"""
        if function_name not in self.call_graph.symbols:
            return {}

        # Functions that would be affected if this function is removed
        affected_callers = set(self._reverse_adjacency_list.get(function_name, []))

        # Functions that this function depends on
        dependencies = set(self._adjacency_list.get(function_name, []))

        # Estimate cascading effects
        cascading_effects = set()
        for caller in affected_callers:
            # If caller only calls this function, it might become dead code
            caller_dependencies = self._adjacency_list.get(caller, [])
            if len(caller_dependencies) == 1 and function_name in caller_dependencies:
                cascading_effects.add(caller)

        return {
            'direct_callers': list(affected_callers),
            'dependencies': list(dependencies),
            'potential_dead_code': list(cascading_effects),
            'impact_score': len(affected_callers) + len(cascading_effects),
            'is_critical': len(affected_callers) > 3 or len(cascading_effects) > 0
        }