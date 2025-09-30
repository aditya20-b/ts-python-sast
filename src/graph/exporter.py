"""
Graph export functionality for DOT, JSON, and other formats
"""

import json
from typing import Dict, List, Set, Optional, Any, TextIO
from datetime import datetime
from pathlib import Path

from .models import CallGraph, GraphExportOptions, GraphExportFormat, GraphLayoutHint, NodeType, CallType


class GraphExporter:
    """Exports call graphs to various formats"""

    def __init__(self, call_graph: CallGraph):
        self.call_graph = call_graph

    def export(self, output_file: str, options: GraphExportOptions) -> None:
        """Export call graph to specified format"""
        if options.format == GraphExportFormat.DOT:
            self.export_dot(output_file, options)
        elif options.format == GraphExportFormat.JSON:
            self.export_json(output_file, options)
        elif options.format == GraphExportFormat.GRAPHML:
            self.export_graphml(output_file, options)
        elif options.format == GraphExportFormat.CYTOSCAPE:
            self.export_cytoscape(output_file, options)
        else:
            raise ValueError(f"Unsupported export format: {options.format}")

    def export_dot(self, output_file: str, options: GraphExportOptions) -> None:
        """Export call graph to DOT format for Graphviz"""
        with open(output_file, 'w') as f:
            f.write('digraph CallGraph {\n')
            f.write('    rankdir=TB;\n')  # Top-to-bottom layout
            f.write('    node [shape=box, style=rounded];\n')
            f.write('    edge [arrowhead=open];\n\n')

            # Apply layout hints
            if options.layout_hint == GraphLayoutHint.HIERARCHICAL:
                f.write('    rankdir=TB;\n')
            elif options.layout_hint == GraphLayoutHint.FORCE_DIRECTED:
                f.write('    layout=fdp;\n')
            elif options.layout_hint == GraphLayoutHint.CIRCULAR:
                f.write('    layout=circo;\n')
            elif options.layout_hint == GraphLayoutHint.TREE:
                f.write('    layout=dot;\n')

            # Filter functions based on options
            functions_to_include = self._filter_functions(options)

            # Write node definitions
            f.write('    // Function nodes\n')
            for func_name, symbol in self.call_graph.symbols.items():
                if func_name not in functions_to_include:
                    continue

                node_attrs = self._get_dot_node_attributes(symbol, options)
                f.write(f'    "{self._escape_dot_id(func_name)}" {node_attrs};\n')

            # Write external nodes if requested
            if options.include_external:
                f.write('\n    // External functions\n')
                for ext_func in self.call_graph.external_calls:
                    if not ext_func.startswith('<builtin>') or options.include_unresolved:
                        ext_attrs = '[shape=ellipse, style=dashed, color=gray]'
                        f.write(f'    "{self._escape_dot_id(ext_func)}" {ext_attrs};\n')

            # Write edges
            f.write('\n    // Call relationships\n')
            for edge in self.call_graph.edges:
                if (edge.caller in functions_to_include and
                    (edge.callee in functions_to_include or
                     (options.include_external and edge.callee in self.call_graph.external_calls))):

                    edge_attrs = self._get_dot_edge_attributes(edge, options)
                    caller_id = self._escape_dot_id(edge.caller)
                    callee_id = self._escape_dot_id(edge.callee)
                    f.write(f'    "{caller_id}" -> "{callee_id}" {edge_attrs};\n')

            # Add clustering if requested
            if options.clustering:
                self._add_dot_clusters(f, functions_to_include)

            f.write('}\n')

    def export_json(self, output_file: str, options: GraphExportOptions) -> None:
        """Export call graph to JSON format"""
        functions_to_include = self._filter_functions(options)

        # Build nodes
        nodes = []
        for func_name, symbol in self.call_graph.symbols.items():
            if func_name not in functions_to_include:
                continue

            node = {
                'id': func_name,
                'name': symbol.name,
                'type': symbol.node_type.value,
                'file': symbol.file_path,
                'line': symbol.start_line,
                'complexity': symbol.complexity,
                'is_reachable': self.call_graph.is_reachable(func_name),
                'is_entry_point': func_name in self.call_graph.entry_points
            }

            # Add optional attributes
            if 'parameters' in options.node_attributes:
                node['parameters'] = symbol.parameters
            if 'decorators' in options.node_attributes:
                node['decorators'] = symbol.decorators
            if 'docstring' in options.node_attributes:
                node['docstring'] = symbol.docstring

            nodes.append(node)

        # Add external nodes if requested
        if options.include_external:
            for ext_func, count in self.call_graph.external_calls.items():
                if not ext_func.startswith('<builtin>') or options.include_unresolved:
                    nodes.append({
                        'id': ext_func,
                        'name': ext_func.split('.')[-1] if '.' in ext_func else ext_func,
                        'type': 'external',
                        'call_count': count,
                        'is_reachable': False,
                        'is_entry_point': False
                    })

        # Build edges
        edges = []
        for edge in self.call_graph.edges:
            if (edge.caller in functions_to_include and
                (edge.callee in functions_to_include or
                 (options.include_external and edge.callee in self.call_graph.external_calls))):

                edge_data = {
                    'source': edge.caller,
                    'target': edge.callee,
                    'call_type': edge.call_type.value,
                    'line': edge.line,
                    'confidence': edge.confidence,
                    'is_conditional': edge.is_conditional
                }

                # Add optional attributes
                if 'call_expression' in options.edge_attributes:
                    edge_data['call_expression'] = edge.call_expression

                edges.append(edge_data)

        # Build complete graph structure
        graph_data = {
            'metadata': {
                'tool': 'ts-sast',
                'version': '0.1.0',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'file_path': self.call_graph.file_path,
                'export_options': options.dict()
            },
            'statistics': {
                'total_nodes': len(nodes),
                'total_edges': len(edges),
                'entry_points': len(self.call_graph.entry_points),
                'reachable_functions': len([n for n in nodes if n.get('is_reachable', False)])
            },
            'nodes': nodes,
            'edges': edges
        }

        with open(output_file, 'w') as f:
            json.dump(graph_data, f, indent=2)

    def export_graphml(self, output_file: str, options: GraphExportOptions) -> None:
        """Export call graph to GraphML format"""
        functions_to_include = self._filter_functions(options)

        with open(output_file, 'w') as f:
            f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
            f.write('<graphml xmlns="http://graphml.graphdrawing.org/xmlns"\n')
            f.write('    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n')
            f.write('    xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns\n')
            f.write('    http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd">\n\n')

            # Define attributes
            f.write('    <!-- Node attributes -->\n')
            f.write('    <key id="name" for="node" attr.name="name" attr.type="string"/>\n')
            f.write('    <key id="type" for="node" attr.name="type" attr.type="string"/>\n')
            f.write('    <key id="complexity" for="node" attr.name="complexity" attr.type="int"/>\n')
            f.write('    <key id="reachable" for="node" attr.name="reachable" attr.type="boolean"/>\n')
            f.write('    <key id="entry_point" for="node" attr.name="entry_point" attr.type="boolean"/>\n')

            f.write('\n    <!-- Edge attributes -->\n')
            f.write('    <key id="call_type" for="edge" attr.name="call_type" attr.type="string"/>\n')
            f.write('    <key id="confidence" for="edge" attr.name="confidence" attr.type="double"/>\n')
            f.write('    <key id="conditional" for="edge" attr.name="conditional" attr.type="boolean"/>\n')

            f.write('\n    <graph id="CallGraph" edgedefault="directed">\n')

            # Write nodes
            f.write('        <!-- Nodes -->\n')
            for func_name, symbol in self.call_graph.symbols.items():
                if func_name not in functions_to_include:
                    continue

                node_id = self._escape_xml_id(func_name)
                f.write(f'        <node id="{node_id}">\n')
                f.write(f'            <data key="name">{self._escape_xml(symbol.name)}</data>\n')
                f.write(f'            <data key="type">{symbol.node_type.value}</data>\n')
                f.write(f'            <data key="complexity">{symbol.complexity}</data>\n')
                f.write(f'            <data key="reachable">{self.call_graph.is_reachable(func_name)}</data>\n')
                f.write(f'            <data key="entry_point">{func_name in self.call_graph.entry_points}</data>\n')
                f.write('        </node>\n')

            # Write edges
            f.write('\n        <!-- Edges -->\n')
            edge_id = 0
            for edge in self.call_graph.edges:
                if (edge.caller in functions_to_include and
                    edge.callee in functions_to_include):

                    source_id = self._escape_xml_id(edge.caller)
                    target_id = self._escape_xml_id(edge.callee)
                    f.write(f'        <edge id="e{edge_id}" source="{source_id}" target="{target_id}">\n')
                    f.write(f'            <data key="call_type">{edge.call_type.value}</data>\n')
                    f.write(f'            <data key="confidence">{edge.confidence}</data>\n')
                    f.write(f'            <data key="conditional">{edge.is_conditional}</data>\n')
                    f.write('        </edge>\n')
                    edge_id += 1

            f.write('    </graph>\n')
            f.write('</graphml>\n')

    def export_cytoscape(self, output_file: str, options: GraphExportOptions) -> None:
        """Export call graph to Cytoscape.js JSON format"""
        functions_to_include = self._filter_functions(options)

        elements = []

        # Add nodes
        for func_name, symbol in self.call_graph.symbols.items():
            if func_name not in functions_to_include:
                continue

            node_data = {
                'id': func_name,
                'name': symbol.name,
                'type': symbol.node_type.value,
                'complexity': symbol.complexity,
                'reachable': self.call_graph.is_reachable(func_name),
                'entry_point': func_name in self.call_graph.entry_points
            }

            elements.append({
                'data': node_data,
                'group': 'nodes'
            })

        # Add edges
        for edge in self.call_graph.edges:
            if (edge.caller in functions_to_include and
                edge.callee in functions_to_include):

                edge_data = {
                    'id': f"{edge.caller}-{edge.callee}",
                    'source': edge.caller,
                    'target': edge.callee,
                    'call_type': edge.call_type.value,
                    'confidence': edge.confidence,
                    'conditional': edge.is_conditional
                }

                elements.append({
                    'data': edge_data,
                    'group': 'edges'
                })

        # Create Cytoscape.js format
        cytoscape_data = {
            'elements': elements,
            'layout': {
                'name': 'dagre',  # Hierarchical layout
                'directed': True,
                'spacingFactor': 1.5
            },
            'style': self._get_cytoscape_style(),
            'metadata': {
                'tool': 'ts-sast',
                'version': '0.1.0',
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
        }

        with open(output_file, 'w') as f:
            json.dump(cytoscape_data, f, indent=2)

    def _filter_functions(self, options: GraphExportOptions) -> Set[str]:
        """Filter functions based on export options"""
        if options.only_reachable:
            return self.call_graph.reachable_nodes.copy()
        else:
            return set(self.call_graph.symbols.keys())

    def _get_dot_node_attributes(self, symbol, options: GraphExportOptions) -> str:
        """Get DOT attributes for a node"""
        attrs = []

        # Base styling
        if symbol.node_type == NodeType.METHOD:
            attrs.append('shape=ellipse')
        else:
            attrs.append('shape=box')

        # Color based on reachability
        if self.call_graph.is_reachable(symbol.qualified_name):
            attrs.append('color=blue')
        else:
            attrs.append('color=gray')

        # Special styling for entry points
        if symbol.qualified_name in self.call_graph.entry_points:
            attrs.append('style="bold,filled"')
            attrs.append('fillcolor=lightgreen')

        # Complexity-based styling
        if symbol.complexity > 10:
            attrs.append('penwidth=3')

        # Label
        label = symbol.name
        if 'parameters' in options.node_attributes:
            params = ', '.join(symbol.parameters[:3])  # Limit for readability
            if len(symbol.parameters) > 3:
                params += '...'
            label += f'({params})'

        attrs.append(f'label="{label}"')

        return '[' + ', '.join(attrs) + ']'

    def _get_dot_edge_attributes(self, edge, options: GraphExportOptions) -> str:
        """Get DOT attributes for an edge"""
        attrs = []

        # Style based on call type
        if edge.call_type == CallType.RECURSIVE:
            attrs.append('color=red')
            attrs.append('style=bold')
        elif edge.call_type == CallType.INDIRECT:
            attrs.append('style=dashed')

        # Style based on confidence
        if edge.confidence < 0.7:
            attrs.append('color=orange')

        # Conditional calls
        if edge.is_conditional:
            attrs.append('style=dotted')

        # Label with line number
        if 'line_numbers' in options.edge_attributes:
            attrs.append(f'label="{edge.line}"')

        return '[' + ', '.join(attrs) + ']' if attrs else ''

    def _add_dot_clusters(self, f: TextIO, functions: Set[str]) -> None:
        """Add clustering to DOT output by file or module"""
        # Group functions by file
        file_groups = {}
        for func_name in functions:
            symbol = self.call_graph.symbols[func_name]
            file_name = Path(symbol.file_path).stem
            if file_name not in file_groups:
                file_groups[file_name] = []
            file_groups[file_name].append(func_name)

        # Create subgraphs for each file
        for i, (file_name, funcs) in enumerate(file_groups.items()):
            if len(funcs) > 1:  # Only cluster if multiple functions
                f.write(f'\n    subgraph cluster_{i} {{\n')
                f.write(f'        label="{file_name}";\n')
                f.write('        style=rounded;\n')
                f.write('        color=lightgray;\n')
                for func in funcs:
                    f.write(f'        "{self._escape_dot_id(func)}";\n')
                f.write('    }\n')

    def _get_cytoscape_style(self) -> List[Dict[str, Any]]:
        """Get Cytoscape.js style definitions"""
        return [
            {
                'selector': 'node',
                'style': {
                    'label': 'data(name)',
                    'background-color': '#666',
                    'color': 'white',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '10px',
                    'width': 'mapData(complexity, 1, 20, 20, 60)',
                    'height': 'mapData(complexity, 1, 20, 20, 60)'
                }
            },
            {
                'selector': 'node[entry_point = true]',
                'style': {
                    'background-color': '#90EE90',
                    'border-width': '2px',
                    'border-color': '#008000'
                }
            },
            {
                'selector': 'node[reachable = false]',
                'style': {
                    'background-color': '#999',
                    'opacity': '0.5'
                }
            },
            {
                'selector': 'edge',
                'style': {
                    'curve-style': 'bezier',
                    'target-arrow-shape': 'triangle',
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'width': 'mapData(confidence, 0, 1, 1, 3)'
                }
            },
            {
                'selector': 'edge[call_type = "recursive"]',
                'style': {
                    'line-color': '#ff0000',
                    'target-arrow-color': '#ff0000'
                }
            }
        ]

    def _escape_dot_id(self, text: str) -> str:
        """Escape text for DOT identifiers"""
        return text.replace('"', '\\"').replace('\n', '\\n')

    def _escape_xml_id(self, text: str) -> str:
        """Escape text for XML identifiers"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;')

    def _escape_xml(self, text: str) -> str:
        """Escape text for XML content"""
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')