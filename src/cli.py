"""
Command-line interface for ts-sast
"""

import os
from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console

from .rules.engine import RuleEngine
from .rules.models import Severity
from .report.console import ConsoleReporter
from .report.json_reporter import JSONReporter
from .report.sarif import SARIFReporter
from .graph.builder import CallGraphBuilder
from .graph.analyzer import ReachabilityAnalyzer
from .graph.exporter import GraphExporter
from .graph.models import GraphExportOptions, GraphExportFormat, GraphLayoutHint
from .parsing.parser import PythonParser

# Initialize typer app
app = typer.Typer(
    name="ts-sast",
    help="Tree-sitter based Static Analysis Security Testing tool",
    add_completion=False
)

console = Console()

# Global options
def version_callback(value: bool):
    if value:
        typer.echo("ts-sast version 0.1.0")
        raise typer.Exit()

@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit"
    )
):
    """Tree-sitter based Static Analysis Security Testing tool"""
    pass


@app.command()
def scan(
    path: str = typer.Argument(..., help="File or directory to scan"),
    rules_dir: str = typer.Option(
        "rules/python", "--rules", "-r",
        help="Directory containing rule files"
    ),
    output_format: str = typer.Option(
        "console", "--format", "-f",
        help="Output format: console, json, sarif, text"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file (default: stdout for console, auto-generated for others)"
    ),
    severity: str = typer.Option(
        "low", "--severity", "-s",
        help="Minimum severity level: low, medium, high, critical"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress console output"
    ),
    show_code: bool = typer.Option(
        True, "--show-code/--no-code",
        help="Show code snippets in console output"
    ),
    rule_ids: Optional[List[str]] = typer.Option(
        None, "--rule", help="Specific rules to run (can be repeated)"
    ),
    exclude_rules: Optional[List[str]] = typer.Option(
        None, "--exclude", help="Rules to exclude (can be repeated)"
    ),
    color: bool = typer.Option(
        True, "--color/--no-color",
        help="Enable/disable colored output"
    )
):
    """Scan files for security issues"""
    try:
        # Validate severity
        try:
            min_severity = Severity(severity.lower())
        except ValueError:
            typer.echo(f"Invalid severity: {severity}. Use: low, medium, high, critical")
            raise typer.Exit(1)

        # Initialize rule engine
        if not Path(rules_dir).exists():
            typer.echo(f"Rules directory not found: {rules_dir}")
            raise typer.Exit(1)

        engine = RuleEngine()
        loaded_rules = engine.load_rules_from_directory(rules_dir)

        if loaded_rules == 0:
            typer.echo(f"No rules loaded from {rules_dir}")
            raise typer.Exit(1)

        if not quiet:
            console.print(f"✅ Loaded {loaded_rules} rules from {rules_dir}")

        # Filter rules if specified
        if exclude_rules:
            original_count = len(engine.rules)
            engine.rules = [r for r in engine.rules if r.id not in exclude_rules]
            excluded_count = original_count - len(engine.rules)
            if not quiet and excluded_count > 0:
                console.print(f"⚠️  Excluded {excluded_count} rules")

        # Collect files to scan
        target_path = Path(path)
        if not target_path.exists():
            typer.echo(f"Path not found: {path}")
            raise typer.Exit(1)

        files_to_scan = []
        if target_path.is_file():
            if target_path.suffix == '.py':
                files_to_scan.append(str(target_path))
            else:
                typer.echo(f"Unsupported file type: {target_path.suffix}")
                raise typer.Exit(1)
        else:
            # Scan directory for Python files
            files_to_scan = [str(f) for f in target_path.rglob("*.py")]

        if not files_to_scan:
            typer.echo("No Python files found to scan")
            raise typer.Exit(1)

        if not quiet:
            console.print(f"🔍 Scanning {len(files_to_scan)} files...")

        # Scan files
        results = []
        for file_path in files_to_scan:
            result = engine.scan_file(
                file_path,
                rule_ids=rule_ids,
                min_severity=min_severity
            )
            results.append(result)

        # Generate output
        if output_format == "console":
            reporter = ConsoleReporter(use_colors=color, quiet=quiet)

            # Show rule stats
            if not quiet:
                stats = engine.get_statistics()
                reporter.print_rule_stats(stats)

            # Show summary
            reporter.print_summary(results)

            # Show detailed findings
            if any(result.findings for result in results):
                reporter.print_findings(results, show_code, min_severity)
            else:
                reporter.print_no_findings()

            # Show errors
            reporter.print_errors(results)

            # Show performance stats
            reporter.print_performance_stats(results)

            # Export to text file if requested
            if output_file:
                reporter.export_text(results, output_file)
                if not quiet:
                    console.print(f"📁 Results exported to {output_file}")

        elif output_format == "json":
            reporter = JSONReporter(pretty=True)
            output_file = output_file or "ts-sast-results.json"
            reporter.export_results(results, output_file)
            if not quiet:
                console.print(f"📁 JSON results exported to {output_file}")

        elif output_format == "sarif":
            reporter = SARIFReporter()
            output_file = output_file or "ts-sast-results.sarif"

            # Get rules info for SARIF
            rules_info = {}
            for rule in engine.rules:
                rules_info[rule.id] = {
                    "title": rule.title,
                    "description": rule.description,
                    "message": rule.message,
                    "severity": rule.severity.value,
                    "tags": rule.tags,
                    "references": rule.references
                }

            reporter.export_sarif(results, output_file, rules_info)
            if not quiet:
                console.print(f"📁 SARIF results exported to {output_file}")

        # Exit with non-zero code if high severity findings
        total_findings = sum(len(result.findings) for result in results)
        high_severity_findings = sum(
            1 for result in results
            for finding in result.findings
            if finding.severity in [Severity.HIGH, Severity.CRITICAL]
        )

        if high_severity_findings > 0:
            raise typer.Exit(1)
        elif total_findings > 0:
            raise typer.Exit(2)  # Medium/low findings
        else:
            raise typer.Exit(0)  # No findings

    except Exception as e:
        if not quiet:
            console.print(f"❌ Error: {e}")
        raise typer.Exit(1)


@app.command()
def rules(
    rules_dir: str = typer.Option(
        "rules/python", "--rules-dir", "-r",
        help="Directory containing rule files"
    ),
    format: str = typer.Option(
        "table", "--format", "-f",
        help="Output format: table, json, ids"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity: low, medium, high, critical"
    ),
    tag: Optional[str] = typer.Option(
        None, "--tag", "-t",
        help="Filter by tag"
    )
):
    """List available rules"""
    try:
        # Load rules
        engine = RuleEngine()
        loaded_rules = engine.load_rules_from_directory(rules_dir)

        if loaded_rules == 0:
            console.print(f"No rules found in {rules_dir}")
            raise typer.Exit(1)

        # Filter rules
        filtered_rules = engine.rules

        if severity:
            try:
                severity_filter = Severity(severity.lower())
                filtered_rules = [r for r in filtered_rules if r.severity == severity_filter]
            except ValueError:
                console.print(f"Invalid severity: {severity}")
                raise typer.Exit(1)

        if tag:
            filtered_rules = [r for r in filtered_rules if r.tags and tag in r.tags]

        if not filtered_rules:
            console.print("No rules match the specified filters")
            raise typer.Exit(0)

        # Output results
        if format == "table":
            from rich.table import Table

            table = Table(title=f"Security Rules ({len(filtered_rules)} rules)")
            table.add_column("ID", style="bold")
            table.add_column("Title")
            table.add_column("Severity")
            table.add_column("Tags")

            for rule in sorted(filtered_rules, key=lambda r: (r.severity.value, r.id)):
                severity_color = {
                    "low": "blue",
                    "medium": "yellow",
                    "high": "red",
                    "critical": "bold red"
                }.get(rule.severity.value, "white")

                tags_str = ", ".join(rule.tags) if rule.tags else ""

                table.add_row(
                    rule.id,
                    rule.title,
                    f"[{severity_color}]{rule.severity.value}[/{severity_color}]",
                    tags_str
                )

            console.print(table)

        elif format == "json":
            import json
            rules_data = []
            for rule in filtered_rules:
                rules_data.append({
                    "id": rule.id,
                    "title": rule.title,
                    "severity": rule.severity.value,
                    "message": rule.message,
                    "tags": rule.tags or [],
                    "description": rule.description
                })

            print(json.dumps(rules_data, indent=2))

        elif format == "ids":
            for rule in sorted(filtered_rules, key=lambda r: r.id):
                print(rule.id)

    except Exception as e:
        console.print(f"❌ Error: {e}")
        raise typer.Exit(1)


@app.command()
def validate(
    rules_dir: str = typer.Argument(..., help="Directory containing rule files"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed validation info")
):
    """Validate rule files"""
    try:
        rules_path = Path(rules_dir)
        if not rules_path.exists():
            console.print(f"Rules directory not found: {rules_dir}")
            raise typer.Exit(1)

        yaml_files = list(rules_path.glob("**/*.yaml")) + list(rules_path.glob("**/*.yml"))

        if not yaml_files:
            console.print(f"No YAML files found in {rules_dir}")
            raise typer.Exit(1)

        console.print(f"🔍 Validating {len(yaml_files)} rule files...")

        valid_files = 0
        total_rules = 0
        errors = []

        for yaml_file in yaml_files:
            try:
                engine = RuleEngine()
                count = engine.load_rules_from_file(str(yaml_file))

                if count > 0:
                    valid_files += 1
                    total_rules += count
                    if verbose:
                        console.print(f"✅ {yaml_file.name}: {count} rules")
                else:
                    errors.append(f"{yaml_file.name}: No valid rules found")
                    if verbose:
                        console.print(f"⚠️  {yaml_file.name}: No valid rules")

            except Exception as e:
                errors.append(f"{yaml_file.name}: {e}")
                if verbose:
                    console.print(f"❌ {yaml_file.name}: {e}")

        # Summary
        console.print(f"\n📊 Validation Summary:")
        console.print(f"   Valid files: {valid_files}/{len(yaml_files)}")
        console.print(f"   Total rules: {total_rules}")

        if errors:
            console.print(f"   Errors: {len(errors)}")
            if not verbose:
                console.print("\n❌ Errors found:")
                for error in errors[:5]:  # Show first 5 errors
                    console.print(f"   {error}")
                if len(errors) > 5:
                    console.print(f"   ... and {len(errors) - 5} more (use --verbose to see all)")

        if errors:
            raise typer.Exit(1)
        else:
            console.print("✅ All rule files are valid!")

    except Exception as e:
        console.print(f"❌ Error: {e}")
        raise typer.Exit(1)


@app.command()
def demo(
    output_dir: str = typer.Option(
        "demo", "--output", "-o",
        help="Output directory for demo files"
    )
):
    """Generate demo files with security issues"""
    demo_dir = Path(output_dir)
    demo_dir.mkdir(exist_ok=True)

    # Create vulnerable demo file
    vulnerable_code = '''#!/usr/bin/env python3
"""
Demo file with various security issues for ts-sast testing
"""

import os
import subprocess
import pickle
import yaml
import hashlib
import requests

# PY.EVAL.USE - Dangerous eval usage
def dangerous_eval(user_input):
    result = eval(user_input)  # SECURITY ISSUE: Code injection
    return result

# PY.SUBPROCESS.SHELL - Shell injection
def run_command(filename):
    subprocess.run(f"ls -la {filename}", shell=True)  # SECURITY ISSUE: Command injection

# PY.OS.SYSTEM - OS system usage
def delete_file(filename):
    os.system(f"rm {filename}")  # SECURITY ISSUE: Command injection

# PY.YAML.UNSAFE_LOAD - Unsafe YAML loading
def load_config(config_data):
    config = yaml.load(config_data)  # SECURITY ISSUE: Code execution via YAML
    return config

# PY.PICKLE.LOAD - Unsafe pickle deserialization
def load_data(data):
    obj = pickle.loads(data)  # SECURITY ISSUE: Code execution via pickle
    return obj

# PY.HASH.WEAK - Weak cryptographic hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # SECURITY ISSUE: Weak hash

# PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
def fetch_data(url):
    response = requests.get(url, verify=False)  # SECURITY ISSUE: MITM vulnerability
    return response.text

# PY.SECRET.HARDCODED - Hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # SECURITY ISSUE: Hardcoded secret
DATABASE_PASSWORD = "super_secret_password"  # SECURITY ISSUE: Hardcoded password

def main():
    # Demo usage (don't actually run this!)
    user_data = input("Enter some data: ")
    dangerous_eval(user_data)

    run_command("test.txt")
    delete_file("temp.log")

    yaml_data = "key: value"
    config = load_config(yaml_data)

    pickle_data = b"arbitrary bytes"
    obj = load_data(pickle_data)

    password_hash = hash_password("mypassword")

    data = fetch_data("https://api.example.com/data")

if __name__ == "__main__":
    main()
'''

    # Create safe demo file
    safe_code = '''#!/usr/bin/env python3
"""
Demo file showing secure alternatives to common security issues
"""

import os
import subprocess
import json
import yaml
import hashlib
import requests
import shlex
import ast

# SECURE: Use ast.literal_eval for safe evaluation
def safe_eval(user_input):
    try:
        result = ast.literal_eval(user_input)  # SECURE: Only evaluates literals
        return result
    except (ValueError, SyntaxError):
        return None

# SECURE: Use subprocess with list arguments
def run_command_safe(filename):
    subprocess.run(["ls", "-la", filename])  # SECURE: No shell injection possible

# SECURE: Use subprocess instead of os.system
def delete_file_safe(filename):
    subprocess.run(["rm", filename])  # SECURE: No shell injection

# SECURE: Use safe YAML loading
def load_config_safe(config_data):
    config = yaml.safe_load(config_data)  # SECURE: Safe YAML loading
    return config

# SECURE: Use JSON instead of pickle for untrusted data
def load_data_safe(json_data):
    obj = json.loads(json_data)  # SECURE: JSON is safe for deserialization
    return obj

# SECURE: Use strong cryptographic hash
def hash_password_safe(password):
    return hashlib.sha256(password.encode()).hexdigest()  # SECURE: Strong hash

# SECURE: Use proper SSL verification
def fetch_data_safe(url):
    response = requests.get(url)  # SECURE: SSL verification enabled by default
    return response.text

# SECURE: Use environment variables for secrets
API_KEY = os.environ.get("API_KEY")  # SECURE: Load from environment
DATABASE_PASSWORD = os.environ.get("DB_PASSWORD")  # SECURE: Load from environment

def main():
    # Demo usage of secure alternatives
    user_data = "{'key': 'value'}"
    safe_result = safe_eval(user_data)

    run_command_safe("test.txt")
    delete_file_safe("temp.log")

    yaml_data = "key: value"
    config = load_config_safe(yaml_data)

    json_data = '{"key": "value"}'
    obj = load_data_safe(json_data)

    password_hash = hash_password_safe("mypassword")

    if API_KEY:  # Check if API key is available
        data = fetch_data_safe("https://api.example.com/data")

if __name__ == "__main__":
    main()
'''

    # Write demo files
    (demo_dir / "vulnerable.py").write_text(vulnerable_code)
    (demo_dir / "secure.py").write_text(safe_code)

    console.print(f"✅ Demo files created in {demo_dir}/")
    console.print(f"   📁 vulnerable.py - Contains security issues")
    console.print(f"   📁 secure.py - Shows secure alternatives")
    console.print(f"\nTry: ts-sast scan {demo_dir}/vulnerable.py")


@app.command()
def graph(
    file_path: str = typer.Argument(..., help="Python file to analyze"),
    format: str = typer.Option(
        "dot", "--format", "-f",
        help="Output format: dot, json, graphml, cytoscape"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o",
        help="Output file (default: auto-generated)"
    ),
    layout: str = typer.Option(
        "hierarchical", "--layout", "-l",
        help="Layout hint: hierarchical, force_directed, circular, tree"
    ),
    entry_points: Optional[List[str]] = typer.Option(
        None, "--entry", help="Entry point functions (can be repeated)"
    ),
    reachable_only: bool = typer.Option(
        False, "--reachable-only",
        help="Only include reachable functions"
    ),
    include_external: bool = typer.Option(
        False, "--include-external",
        help="Include external function calls"
    ),
    clustering: bool = typer.Option(
        False, "--cluster",
        help="Group functions by file/module"
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress console output"
    )
):
    """Generate call graph for Python file"""
    try:
        # Validate file
        target_path = Path(file_path)
        if not target_path.exists():
            typer.echo(f"File not found: {file_path}")
            raise typer.Exit(1)

        if target_path.suffix != '.py':
            typer.echo(f"File must be a Python file (.py): {file_path}")
            raise typer.Exit(1)

        if not quiet:
            console.print(f"🔍 Analyzing call graph for {file_path}...")

        # Parse file and build call graph
        parser = PythonParser()
        ast = parser.parse_file(file_path)
        if not ast:
            typer.echo(f"Failed to parse file: {file_path}")
            raise typer.Exit(1)

        builder = CallGraphBuilder(file_path)
        call_graph = builder.build(ast)

        # Perform reachability analysis
        analyzer = ReachabilityAnalyzer(call_graph)
        reachability = analyzer.analyze(entry_points or None)

        # Generate output filename if not specified
        if not output:
            stem = target_path.stem
            format_ext = {"dot": "dot", "json": "json", "graphml": "xml", "cytoscape": "json"}
            ext = format_ext.get(format, format)
            output = f"{stem}_callgraph.{ext}"

        # Set up export options
        try:
            export_format = GraphExportFormat(format.lower())
            layout_hint = GraphLayoutHint(layout.lower())
        except ValueError as e:
            typer.echo(f"Invalid format or layout: {e}")
            raise typer.Exit(1)

        export_options = GraphExportOptions(
            format=export_format,
            include_external=include_external,
            only_reachable=reachable_only,
            layout_hint=layout_hint,
            clustering=clustering,
            node_attributes=['parameters', 'decorators'] if include_external else [],
            edge_attributes=['call_expression'] if include_external else []
        )

        # Export graph
        exporter = GraphExporter(call_graph)
        exporter.export(output, export_options)

        # Show statistics
        if not quiet:
            stats = analyzer.generate_statistics()
            console.print("\n📊 Call Graph Statistics:")
            console.print(f"   Functions: {stats.total_functions}")
            console.print(f"   Call edges: {stats.total_calls}")
            console.print(f"   Entry points: {stats.entry_points}")
            console.print(f"   Reachable: {stats.reachable_functions}")
            console.print(f"   External calls: {stats.external_calls}")

            console.print(f"\n📁 Graph exported to {output}")

    except Exception as e:
        if not quiet:
            console.print(f"❌ Error: {e}")
        raise typer.Exit(1)


@app.command()
def analyze(
    file_path: str = typer.Argument(..., help="Python file to analyze"),
    entry_points: Optional[List[str]] = typer.Option(
        None, "--entry", help="Entry point functions"
    ),
    find_cycles: bool = typer.Option(
        False, "--cycles",
        help="Find cycles in call graph"
    ),
    find_dead_code: bool = typer.Option(
        False, "--dead-code",
        help="Find potentially dead code"
    ),
    critical_functions: int = typer.Option(
        0, "--critical", help="Show top N critical functions"
    ),
    impact_analysis: Optional[str] = typer.Option(
        None, "--impact", help="Analyze impact of removing specific function"
    ),
    output_format: str = typer.Option(
        "table", "--format", help="Output format: table, json"
    )
):
    """Perform advanced call graph analysis"""
    try:
        # Parse file and build call graph
        target_path = Path(file_path)
        if not target_path.exists():
            typer.echo(f"File not found: {file_path}")
            raise typer.Exit(1)

        parser = PythonParser()
        ast = parser.parse_file(file_path)
        if not ast:
            typer.echo(f"Failed to parse file: {file_path}")
            raise typer.Exit(1)

        builder = CallGraphBuilder(file_path)
        call_graph = builder.build(ast)
        analyzer = ReachabilityAnalyzer(call_graph)

        # Perform requested analyses
        results = {}

        # Basic statistics
        stats = analyzer.generate_statistics()
        results['statistics'] = stats

        # Reachability analysis
        reachability = analyzer.analyze(entry_points or None)
        results['reachability'] = reachability

        # Find cycles
        if find_cycles:
            cycles = analyzer.find_cycles()
            results['cycles'] = cycles

        # Find dead code
        if find_dead_code:
            dead_code = analyzer.find_dead_code()
            results['dead_code'] = dead_code

        # Critical functions analysis
        if critical_functions > 0:
            critical = analyzer.find_critical_functions(critical_functions)
            results['critical_functions'] = critical

        # Impact analysis
        if impact_analysis:
            if impact_analysis in call_graph.symbols:
                impact = analyzer.estimate_impact(impact_analysis)
                results['impact_analysis'] = {impact_analysis: impact}
            else:
                console.print(f"⚠️ Function '{impact_analysis}' not found")

        # Output results
        if output_format == "json":
            import json
            # Convert sets to lists for JSON serialization
            json_results = json.loads(json.dumps(results, default=str))
            print(json.dumps(json_results, indent=2))
        else:
            # Table format
            from rich.table import Table
            from rich.panel import Panel

            # Show statistics
            stats_table = Table(title="📊 Call Graph Statistics")
            stats_table.add_column("Metric", style="bold")
            stats_table.add_column("Value", justify="right")

            stats_table.add_row("Total Functions", str(stats.total_functions))
            stats_table.add_row("Total Calls", str(stats.total_calls))
            stats_table.add_row("Entry Points", str(stats.entry_points))
            stats_table.add_row("Reachable Functions", str(stats.reachable_functions))
            stats_table.add_row("Unreachable Functions", str(stats.unreachable_functions))
            stats_table.add_row("External Calls", str(stats.external_calls))
            stats_table.add_row("Max Call Depth", str(stats.max_call_depth))

            console.print(stats_table)

            # Show cycles if requested
            if find_cycles and results.get('cycles'):
                console.print("\n🔄 Detected Cycles:")
                for i, cycle in enumerate(results['cycles'][:5]):  # Limit display
                    cycle_str = " → ".join(cycle)
                    console.print(f"   {i+1}. {cycle_str}")

            # Show dead code if requested
            if find_dead_code and results.get('dead_code'):
                console.print(f"\n💀 Potentially Dead Code ({len(results['dead_code'])} functions):")
                for func in results['dead_code'][:10]:  # Limit display
                    console.print(f"   • {func}")

            # Show critical functions
            if critical_functions > 0 and results.get('critical_functions'):
                console.print(f"\n⚡ Top {critical_functions} Critical Functions:")
                for i, (func, metrics) in enumerate(results['critical_functions']):
                    console.print(f"   {i+1}. {func} (degree: {metrics['total_degree']}, betweenness: {metrics['betweenness']:.2f})")

            # Show impact analysis
            if impact_analysis and results.get('impact_analysis'):
                impact = results['impact_analysis'][impact_analysis]
                console.print(f"\n💥 Impact Analysis for '{impact_analysis}':")
                console.print(f"   Direct callers: {len(impact['direct_callers'])}")
                console.print(f"   Dependencies: {len(impact['dependencies'])}")
                console.print(f"   Impact score: {impact['impact_score']}")
                console.print(f"   Is critical: {'Yes' if impact['is_critical'] else 'No'}")

    except Exception as e:
        console.print(f"❌ Error: {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()