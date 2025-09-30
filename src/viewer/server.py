"""
Simple web server for call graph visualization
"""

import json
import webbrowser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Optional
import threading
import tempfile
import shutil

from ..graph.models import CallGraph
from ..graph.exporter import GraphExporter
from ..graph.models import GraphExportOptions, GraphExportFormat


class ViewerRequestHandler(SimpleHTTPRequestHandler):
    """Custom request handler for serving call graph viewer"""

    def __init__(self, *args, graph_data=None, **kwargs):
        self.graph_data = graph_data
        super().__init__(*args, **kwargs)

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/api/graph':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            if self.graph_data:
                self.wfile.write(json.dumps(self.graph_data).encode())
            else:
                self.wfile.write(b'{}')
        else:
            super().do_GET()


class ViewerServer:
    """Web server for call graph visualization"""

    def __init__(self, call_graph: CallGraph, port: int = 8080):
        self.call_graph = call_graph
        self.port = port
        self.server: Optional[HTTPServer] = None
        self.temp_dir: Optional[Path] = None
        self.server_thread: Optional[threading.Thread] = None

    def start(self, open_browser: bool = True) -> str:
        """Start the web server and optionally open browser"""
        # Create temporary directory for serving files
        self.temp_dir = Path(tempfile.mkdtemp(prefix='ts_sast_viewer_'))

        # Generate HTML and assets
        self._generate_viewer_files()

        # Export graph data
        graph_data = self._export_graph_data()

        # Create custom handler with graph data
        handler_class = lambda *args, **kwargs: ViewerRequestHandler(
            *args, graph_data=graph_data, **kwargs
        )

        # Start HTTP server
        import os
        os.chdir(self.temp_dir)

        self.server = HTTPServer(('localhost', self.port), handler_class)

        # Start server in background thread
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

        url = f"http://localhost:{self.port}"

        if open_browser:
            webbrowser.open(url)

        return url

    def stop(self):
        """Stop the web server and clean up"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

        if self.temp_dir and self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)

    def _generate_viewer_files(self):
        """Generate HTML and assets for the viewer"""
        # Create index.html
        html_content = self._get_html_template()
        (self.temp_dir / 'index.html').write_text(html_content)

        # Create CSS file
        css_content = self._get_css_styles()
        (self.temp_dir / 'style.css').write_text(css_content)

        # Create JavaScript file
        js_content = self._get_javascript()
        (self.temp_dir / 'viewer.js').write_text(js_content)

    def _export_graph_data(self) -> dict:
        """Export call graph data for visualization"""
        exporter = GraphExporter(self.call_graph)

        # Use temporary file to get JSON data
        temp_json = self.temp_dir / 'graph.json'
        export_options = GraphExportOptions(
            format=GraphExportFormat.CYTOSCAPE,
            include_external=True,
            only_reachable=False,
            node_attributes=['parameters', 'decorators'],
            edge_attributes=['call_expression']
        )

        exporter.export(str(temp_json), export_options)

        with open(temp_json) as f:
            return json.load(f)

    def _get_html_template(self) -> str:
        """Get HTML template for the viewer"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TS-SAST Call Graph Viewer</title>
    <link rel="stylesheet" href="style.css">
    <script src="https://unpkg.com/cytoscape@3.21.0/dist/cytoscape.min.js"></script>
    <script src="https://unpkg.com/cytoscape-dagre@2.3.2/cytoscape-dagre.js"></script>
    <script src="https://unpkg.com/dagre@0.8.5/dist/dagre.min.js"></script>
</head>
<body>
    <div class="header">
        <h1>🔍 TS-SAST Call Graph Viewer</h1>
        <div class="controls">
            <button id="layout-btn">Change Layout</button>
            <button id="fit-btn">Fit to Screen</button>
            <button id="export-btn">Export PNG</button>
            <select id="filter-select">
                <option value="all">Show All</option>
                <option value="reachable">Reachable Only</option>
                <option value="entry-points">Entry Points</option>
            </select>
        </div>
    </div>

    <div class="main-content">
        <div class="sidebar">
            <div class="info-panel">
                <h3>Graph Statistics</h3>
                <div id="stats"></div>
            </div>

            <div class="info-panel">
                <h3>Selected Node</h3>
                <div id="node-info">Click on a node to see details</div>
            </div>

            <div class="info-panel">
                <h3>Legend</h3>
                <div class="legend">
                    <div class="legend-item">
                        <div class="legend-color entry-point"></div>
                        <span>Entry Points</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color reachable"></div>
                        <span>Reachable Functions</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color unreachable"></div>
                        <span>Unreachable Functions</span>
                    </div>
                    <div class="legend-item">
                        <div class="legend-color recursive"></div>
                        <span>Recursive Calls</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="graph-container">
            <div id="cy"></div>
        </div>
    </div>

    <script src="viewer.js"></script>
</body>
</html>"""

    def _get_css_styles(self) -> str:
        """Get CSS styles for the viewer"""
        return """* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background-color: #f5f5f5;
    height: 100vh;
    display: flex;
    flex-direction: column;
}

.header {
    background: #2c3e50;
    color: white;
    padding: 1rem 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.header h1 {
    font-size: 1.5rem;
}

.controls {
    display: flex;
    gap: 1rem;
    align-items: center;
}

.controls button,
.controls select {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    background: #3498db;
    color: white;
    cursor: pointer;
    transition: background-color 0.2s;
}

.controls button:hover {
    background: #2980b9;
}

.controls select {
    background: #34495e;
}

.main-content {
    flex: 1;
    display: flex;
    min-height: 0;
}

.sidebar {
    width: 300px;
    background: white;
    border-right: 1px solid #ddd;
    overflow-y: auto;
    padding: 1rem;
}

.info-panel {
    margin-bottom: 2rem;
}

.info-panel h3 {
    color: #2c3e50;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid #3498db;
}

.graph-container {
    flex: 1;
    position: relative;
    background: white;
}

#cy {
    width: 100%;
    height: 100%;
}

#stats {
    font-size: 0.9rem;
    line-height: 1.6;
}

#node-info {
    font-size: 0.9rem;
    line-height: 1.6;
}

.legend {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.legend-item {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9rem;
}

.legend-color {
    width: 16px;
    height: 16px;
    border-radius: 50%;
    border: 2px solid #ddd;
}

.legend-color.entry-point {
    background: #90EE90;
    border-color: #008000;
}

.legend-color.reachable {
    background: #3498db;
    border-color: #2980b9;
}

.legend-color.unreachable {
    background: #999;
    border-color: #777;
}

.legend-color.recursive {
    background: #e74c3c;
    border-color: #c0392b;
}

.stat-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
}

.stat-label {
    font-weight: bold;
}

.function-detail {
    background: #f8f9fa;
    padding: 1rem;
    border-radius: 4px;
    margin-top: 1rem;
}

.function-detail h4 {
    color: #2c3e50;
    margin-bottom: 0.5rem;
}

.function-params {
    font-family: monospace;
    font-size: 0.8rem;
    color: #666;
    background: #f1f1f1;
    padding: 0.3rem;
    border-radius: 3px;
    margin-top: 0.5rem;
}"""

    def _get_javascript(self) -> str:
        """Get JavaScript code for the viewer"""
        return """let cy;
let graphData = {};
let layouts = ['dagre', 'breadthfirst', 'circle', 'grid', 'random'];
let currentLayout = 0;

// Initialize the viewer
async function init() {
    try {
        const response = await fetch('/api/graph');
        graphData = await response.json();

        initCytoscape();
        updateStats();
        setupEventHandlers();
    } catch (error) {
        console.error('Failed to load graph data:', error);
        document.getElementById('stats').innerHTML = '<p>Failed to load graph data</p>';
    }
}

function initCytoscape() {
    cy = cytoscape({
        container: document.getElementById('cy'),

        elements: graphData.elements || [],

        style: [
            {
                selector: 'node',
                style: {
                    'background-color': '#666',
                    'label': 'data(name)',
                    'color': '#fff',
                    'text-valign': 'center',
                    'text-halign': 'center',
                    'font-size': '10px',
                    'width': 'mapData(complexity, 1, 20, 20, 60)',
                    'height': 'mapData(complexity, 1, 20, 20, 60)',
                    'text-wrap': 'wrap',
                    'text-max-width': '80px'
                }
            },
            {
                selector: 'node[entry_point = true]',
                style: {
                    'background-color': '#90EE90',
                    'border-width': '3px',
                    'border-color': '#008000'
                }
            },
            {
                selector: 'node[reachable = false]',
                style: {
                    'background-color': '#999',
                    'opacity': '0.6'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': '3px',
                    'border-color': '#ff6b6b'
                }
            },
            {
                selector: 'edge',
                style: {
                    'curve-style': 'bezier',
                    'target-arrow-shape': 'triangle',
                    'line-color': '#ccc',
                    'target-arrow-color': '#ccc',
                    'width': 'mapData(confidence, 0, 1, 1, 4)',
                    'opacity': 'mapData(confidence, 0, 1, 0.3, 1)'
                }
            },
            {
                selector: 'edge[call_type = "recursive"]',
                style: {
                    'line-color': '#e74c3c',
                    'target-arrow-color': '#e74c3c',
                    'width': '3px'
                }
            },
            {
                selector: 'edge:selected',
                style: {
                    'line-color': '#ff6b6b',
                    'target-arrow-color': '#ff6b6b'
                }
            }
        ],

        layout: {
            name: 'dagre',
            directed: true,
            spacingFactor: 1.5,
            nodeSep: 100,
            edgeSep: 50,
            rankSep: 150
        }
    });

    // Node click handler
    cy.on('tap', 'node', function(evt) {
        const node = evt.target;
        showNodeInfo(node.data());
    });

    // Edge click handler
    cy.on('tap', 'edge', function(evt) {
        const edge = evt.target;
        showEdgeInfo(edge.data());
    });
}

function setupEventHandlers() {
    // Layout button
    document.getElementById('layout-btn').addEventListener('click', function() {
        currentLayout = (currentLayout + 1) % layouts.length;
        const layoutName = layouts[currentLayout];

        let layoutOptions = {
            name: layoutName,
            directed: true,
            animate: true,
            animationDuration: 500
        };

        if (layoutName === 'dagre') {
            layoutOptions.spacingFactor = 1.5;
            layoutOptions.nodeSep = 100;
            layoutOptions.edgeSep = 50;
            layoutOptions.rankSep = 150;
        }

        cy.layout(layoutOptions).run();
        this.textContent = `Layout: ${layoutName}`;
    });

    // Fit button
    document.getElementById('fit-btn').addEventListener('click', function() {
        cy.fit();
    });

    // Export button
    document.getElementById('export-btn').addEventListener('click', function() {
        const png64 = cy.png({scale: 2});
        const link = document.createElement('a');
        link.href = png64;
        link.download = 'call-graph.png';
        link.click();
    });

    // Filter select
    document.getElementById('filter-select').addEventListener('change', function() {
        const filter = this.value;
        filterGraph(filter);
    });
}

function filterGraph(filter) {
    cy.elements().style('display', 'element');

    switch (filter) {
        case 'reachable':
            cy.nodes('[reachable = false]').style('display', 'none');
            break;
        case 'entry-points':
            cy.nodes('[entry_point != true]').style('display', 'none');
            cy.edges().hide();
            // Show edges connected to entry points
            cy.nodes('[entry_point = true]').connectedEdges().style('display', 'element');
            break;
    }
}

function updateStats() {
    if (!graphData.elements) return;

    const nodes = graphData.elements.filter(e => e.group === 'nodes');
    const edges = graphData.elements.filter(e => e.group === 'edges');

    const entryPoints = nodes.filter(n => n.data.entry_point).length;
    const reachableNodes = nodes.filter(n => n.data.reachable).length;
    const unreachableNodes = nodes.length - reachableNodes;
    const recursiveEdges = edges.filter(e => e.data.call_type === 'recursive').length;

    document.getElementById('stats').innerHTML = `
        <div class="stat-item">
            <span class="stat-label">Total Functions:</span>
            <span>${nodes.length}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Total Calls:</span>
            <span>${edges.length}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Entry Points:</span>
            <span>${entryPoints}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Reachable:</span>
            <span>${reachableNodes}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Unreachable:</span>
            <span>${unreachableNodes}</span>
        </div>
        <div class="stat-item">
            <span class="stat-label">Recursive Calls:</span>
            <span>${recursiveEdges}</span>
        </div>
    `;
}

function showNodeInfo(nodeData) {
    const info = `
        <div class="function-detail">
            <h4>${nodeData.name}</h4>
            <p><strong>Type:</strong> ${nodeData.type}</p>
            <p><strong>Complexity:</strong> ${nodeData.complexity || 'N/A'}</p>
            <p><strong>Reachable:</strong> ${nodeData.reachable ? 'Yes' : 'No'}</p>
            <p><strong>Entry Point:</strong> ${nodeData.entry_point ? 'Yes' : 'No'}</p>
            ${nodeData.parameters && nodeData.parameters.length > 0 ?
                `<div class="function-params">Parameters: ${nodeData.parameters.join(', ')}</div>` :
                ''
            }
        </div>
    `;

    document.getElementById('node-info').innerHTML = info;
}

function showEdgeInfo(edgeData) {
    const info = `
        <div class="function-detail">
            <h4>Function Call</h4>
            <p><strong>From:</strong> ${edgeData.source}</p>
            <p><strong>To:</strong> ${edgeData.target}</p>
            <p><strong>Type:</strong> ${edgeData.call_type}</p>
            <p><strong>Confidence:</strong> ${(edgeData.confidence * 100).toFixed(1)}%</p>
            <p><strong>Conditional:</strong> ${edgeData.conditional ? 'Yes' : 'No'}</p>
            ${edgeData.call_expression ?
                `<div class="function-params">Expression: ${edgeData.call_expression}</div>` :
                ''
            }
        </div>
    `;

    document.getElementById('node-info').innerHTML = info;
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', init);"""

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.stop()