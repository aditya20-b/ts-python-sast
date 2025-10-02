"""
Taint analysis reporting
"""

from typing import Dict, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.text import Text
from .models import TaintAnalysisResult, TaintPath, SinkType


class TaintReporter:
    """Reporter for taint analysis results"""

    def __init__(self):
        self.console = Console()

    def report_results(self, result: TaintAnalysisResult) -> None:
        """Print taint analysis results to console"""
        self.console.print()
        self.console.print(Panel.fit(
            f"[bold cyan]Taint Analysis Results[/bold cyan]\n"
            f"File: {result.file_path}",
            border_style="cyan"
        ))

        # Summary statistics
        self._print_summary(result)

        # Print vulnerable paths
        if result.taint_paths:
            vulnerable_paths = [p for p in result.taint_paths if not p.is_sanitized]
            sanitized_paths = [p for p in result.taint_paths if p.is_sanitized]

            if vulnerable_paths:
                self.console.print("\n[bold red]⚠ Vulnerable Taint Paths:[/bold red]")
                self._print_paths(vulnerable_paths)

            if sanitized_paths:
                self.console.print("\n[bold green]✓ Sanitized Paths:[/bold green]")
                self._print_paths(sanitized_paths, show_sanitizers=True)
        else:
            self.console.print("\n[bold green]✓ No taint vulnerabilities found[/bold green]")

        # Print analysis time
        self.console.print(f"\n[dim]Analysis completed in {result.analysis_time_ms:.2f}ms[/dim]")

    def _print_summary(self, result: TaintAnalysisResult) -> None:
        """Print summary statistics"""
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="cyan")
        table.add_column("Count", style="bold")

        table.add_row("Sources Found", str(result.sources_found))
        table.add_row("Sinks Found", str(result.sinks_found))
        table.add_row("Sanitizers Found", str(result.sanitizers_found))
        table.add_row("Total Paths", str(len(result.taint_paths)))
        table.add_row("Vulnerable Paths", f"[red]{result.vulnerable_paths_count}[/red]")
        table.add_row("Sanitized Paths", f"[green]{result.sanitized_paths_count}[/green]")

        self.console.print(table)

    def _print_paths(self, paths: List[TaintPath], show_sanitizers: bool = False) -> None:
        """Print taint paths"""
        # Group by severity
        paths_by_severity = {}
        for path in paths:
            if path.severity not in paths_by_severity:
                paths_by_severity[path.severity] = []
            paths_by_severity[path.severity].append(path)

        # Print in severity order
        for severity in ['critical', 'high', 'medium', 'low']:
            if severity not in paths_by_severity:
                continue

            severity_paths = paths_by_severity[severity]
            severity_color = self._get_severity_color(severity)

            for path in severity_paths:
                self._print_single_path(path, severity_color, show_sanitizers)

    def _print_single_path(
        self,
        path: TaintPath,
        severity_color: str,
        show_sanitizers: bool
    ) -> None:
        """Print a single taint path"""
        # Create path visualization
        tree = Tree(
            f"[{severity_color}]●[/{severity_color}] "
            f"[bold]{path.severity.upper()}[/bold] - "
            f"{self._format_sink_type(path.sink_type)}"
        )

        # Source
        source_node = tree.add(
            f"[cyan]Source:[/cyan] {path.source} "
            f"[dim]({', '.join(str(l.value) for l in path.taint_labels)})[/dim]"
        )
        source_node.add(f"[dim]{path.source_location}:{path.source_line}[/dim]")

        # Flow path
        if path.path_edges:
            flow_node = tree.add(f"[yellow]Flow:[/yellow] {len(path.path_edges)} step(s)")
            for i, edge in enumerate(path.path_edges, 1):
                operation_style = "green" if edge.sanitizer_applied else "white"
                edge_text = f"{i}. {edge.from_var} → {edge.to_var} [dim]({edge.operation})[/dim]"
                if edge.sanitizer_applied:
                    edge_text += f" [green]✓ {edge.sanitizer_applied}[/green]"
                flow_node.add(f"[{operation_style}]{edge_text}[/{operation_style}]")

        # Sink
        sink_node = tree.add(
            f"[{severity_color}]Sink:[/{severity_color}] {path.sink}"
        )
        sink_node.add(f"[dim]{path.sink_location}:{path.sink_line}[/dim]")

        # Sanitizers
        if show_sanitizers and path.sanitizers:
            sanitizer_node = tree.add("[green]Sanitizers Applied:[/green]")
            for sanitizer in path.sanitizers:
                sanitizer_node.add(f"[green]✓ {sanitizer}[/green]")

        self.console.print(tree)
        self.console.print()

    def _get_severity_color(self, severity: str) -> str:
        """Get color for severity level"""
        colors = {
            'critical': 'bright_red',
            'high': 'red',
            'medium': 'yellow',
            'low': 'blue'
        }
        return colors.get(severity.lower(), 'white')

    def _format_sink_type(self, sink_type: SinkType) -> str:
        """Format sink type for display"""
        type_names = {
            SinkType.COMMAND_EXEC: "Command Injection",
            SinkType.CODE_EVAL: "Code Injection",
            SinkType.SQL_EXEC: "SQL Injection",
            SinkType.FILE_WRITE: "File Write",
            SinkType.TEMPLATE_RENDER: "Template Injection",
            SinkType.HTTP_REQUEST: "SSRF",
            SinkType.SERIALIZATION: "Deserialization",
            SinkType.LOG_OUTPUT: "Information Disclosure",
            SinkType.PATH_TRAVERSAL: "Path Traversal"
        }
        return type_names.get(sink_type, str(sink_type))

    def export_json(self, result: TaintAnalysisResult) -> Dict:
        """Export results as JSON"""
        return {
            "file_path": result.file_path,
            "summary": {
                "sources_found": result.sources_found,
                "sinks_found": result.sinks_found,
                "sanitizers_found": result.sanitizers_found,
                "total_paths": len(result.taint_paths),
                "vulnerable_paths": result.vulnerable_paths_count,
                "sanitized_paths": result.sanitized_paths_count,
                "analysis_time_ms": result.analysis_time_ms
            },
            "paths": [
                {
                    "source": {
                        "variable": path.source,
                        "type": path.source_type.value,
                        "location": path.source_location,
                        "line": path.source_line
                    },
                    "sink": {
                        "function": path.sink,
                        "type": path.sink_type.value,
                        "location": path.sink_location,
                        "line": path.sink_line
                    },
                    "taint_labels": [label.value for label in path.taint_labels],
                    "flow": [
                        {
                            "from": edge.from_var,
                            "to": edge.to_var,
                            "operation": edge.operation,
                            "location": f"{edge.location}:{edge.line}",
                            "preserves_taint": edge.preserves_taint,
                            "sanitizer": edge.sanitizer_applied
                        }
                        for edge in path.path_edges
                    ],
                    "is_sanitized": path.is_sanitized,
                    "sanitizers": path.sanitizers,
                    "severity": path.severity,
                    "confidence": path.confidence
                }
                for path in result.taint_paths
            ]
        }

    def print_summary_table(self, results: List[TaintAnalysisResult]) -> None:
        """Print summary table for multiple files"""
        table = Table(title="Taint Analysis Summary")
        table.add_column("File", style="cyan")
        table.add_column("Sources", justify="right")
        table.add_column("Sinks", justify="right")
        table.add_column("Paths", justify="right")
        table.add_column("Vulnerable", justify="right", style="red")
        table.add_column("Sanitized", justify="right", style="green")

        for result in results:
            table.add_row(
                result.file_path,
                str(result.sources_found),
                str(result.sinks_found),
                str(len(result.taint_paths)),
                str(result.vulnerable_paths_count),
                str(result.sanitized_paths_count)
            )

        self.console.print(table)
