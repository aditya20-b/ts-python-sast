"""
Console reporter for terminal output with colors and formatting
"""

from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.syntax import Syntax
from rich import box

from ..rules.models import ScanResult, Finding, Severity


class ConsoleReporter:
    """Rich console reporter for scan results"""

    def __init__(self, use_colors: bool = True, quiet: bool = False):
        self.console = Console(force_terminal=use_colors)
        self.quiet = quiet

        # Severity colors
        self.severity_colors = {
            Severity.LOW: "blue",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red"
        }

        # Severity symbols
        self.severity_symbols = {
            Severity.LOW: "ℹ",
            Severity.MEDIUM: "⚠",
            Severity.HIGH: "⚠",
            Severity.CRITICAL: "🔥"
        }

    def print_summary(self, results: List[ScanResult]) -> None:
        """Print summary of scan results"""
        if self.quiet:
            return

        total_findings = sum(len(result.findings) for result in results)
        total_files = len(results)

        # Count findings by severity
        severity_counts = {severity: 0 for severity in Severity}
        for result in results:
            for finding in result.findings:
                severity_counts[finding.severity] += 1

        # Create summary table
        table = Table(title="📊 Scan Summary", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Count", justify="right")

        table.add_row("Files Scanned", str(total_files))
        table.add_row("Total Findings", str(total_findings))
        table.add_row("", "")  # Separator

        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = severity_counts[severity]
            if count > 0:
                symbol = self.severity_symbols[severity]
                color = self.severity_colors[severity]
                table.add_row(
                    f"{symbol} {severity.value.title()}",
                    Text(str(count), style=color)
                )

        self.console.print(table)
        self.console.print()

    def print_findings(self, results: List[ScanResult], show_code: bool = True,
                      min_severity: Severity = Severity.LOW) -> None:
        """Print detailed findings"""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        min_index = severity_order.index(min_severity)

        for result in results:
            if not result.findings:
                continue

            # Filter findings by severity
            filtered_findings = [
                f for f in result.findings
                if severity_order.index(f.severity) <= min_index
            ]

            if not filtered_findings:
                continue

            # File header
            self.console.print(f"\n📁 [bold blue]{result.file_path}[/bold blue]")
            self.console.print(f"   Found {len(filtered_findings)} finding(s)")

            # Sort findings by severity and line number
            sorted_findings = sorted(
                filtered_findings,
                key=lambda f: (severity_order.index(f.severity), f.location.start_line)
            )

            for finding in sorted_findings:
                self._print_finding(finding, show_code)

    def _print_finding(self, finding: Finding, show_code: bool = True) -> None:
        """Print a single finding"""
        severity = finding.severity
        symbol = self.severity_symbols[severity]
        color = self.severity_colors[severity]

        # Finding header
        location = f"{finding.location.start_line}:{finding.location.start_column}"
        header = f"{symbol} [{color}]{severity.value.upper()}[/{color}] {finding.title}"

        self.console.print(f"\n  {header}")
        self.console.print(f"     Line {location} • Rule: {finding.rule_id}")
        self.console.print(f"     {finding.message}")

        # Show remediation if available
        if finding.remediation:
            self.console.print(f"     💡 [dim]{finding.remediation}[/dim]")

        # Show code snippet
        if show_code and finding.code_snippet:
            self._print_code_snippet(finding)

    def _print_code_snippet(self, finding: Finding) -> None:
        """Print syntax-highlighted code snippet"""
        try:
            # Create syntax-highlighted code
            syntax = Syntax(
                finding.code_snippet,
                "python",
                theme="monokai",
                line_numbers=True,
                start_line=max(1, finding.location.start_line - 2),
                highlight_lines={finding.location.start_line}
            )

            panel = Panel(
                syntax,
                title="📝 Code Context",
                border_style="dim",
                padding=(0, 1)
            )

            self.console.print(panel)

        except Exception:
            # Fallback to plain text
            self.console.print(Panel(
                finding.code_snippet,
                title="📝 Code Context",
                border_style="dim"
            ))

    def print_errors(self, results: List[ScanResult]) -> None:
        """Print scan errors if any"""
        errors = []
        for result in results:
            if result.errors:
                errors.extend([(result.file_path, error) for error in result.errors])

        if not errors:
            return

        self.console.print(f"\n⚠️  [bold red]Scan Errors ({len(errors)})[/bold red]")
        for file_path, error in errors:
            self.console.print(f"   {file_path}: {error}")

    def print_performance_stats(self, results: List[ScanResult]) -> None:
        """Print performance statistics"""
        if self.quiet or not results:
            return

        total_time = sum(result.scan_time_ms for result in results)
        avg_time = total_time / len(results)
        total_rules = sum(result.rules_applied for result in results)

        stats_text = (
            f"⏱️  Scanned {len(results)} files in {total_time:.1f}ms "
            f"(avg: {avg_time:.1f}ms/file) • {total_rules} rule applications"
        )

        self.console.print(f"\n[dim]{stats_text}[/dim]")

    def print_no_findings(self) -> None:
        """Print message when no findings are found"""
        if not self.quiet:
            self.console.print("\n✅ [green]No security issues found![/green]")

    def print_rule_stats(self, engine_stats: Dict[str, Any]) -> None:
        """Print rule engine statistics"""
        if self.quiet:
            return

        total_rules = engine_stats.get('total_rules', 0)
        severity_counts = engine_stats.get('severity_counts', {})

        self.console.print(f"\n📋 Loaded {total_rules} security rules")

        if severity_counts:
            severity_text = []
            for severity, count in severity_counts.items():
                if count > 0:
                    severity_text.append(f"{count} {severity}")

            if severity_text:
                self.console.print(f"     {' • '.join(severity_text)}")

    def export_text(self, results: List[ScanResult], file_path: str) -> None:
        """Export results to a plain text file"""
        with open(file_path, 'w') as f:
            # Capture console output to file
            file_console = Console(file=f, force_terminal=False, width=120)

            file_console.print("TS-SAST Security Scan Results")
            file_console.print("=" * 40)

            for result in results:
                if not result.findings:
                    continue

                file_console.print(f"\nFile: {result.file_path}")
                file_console.print(f"Findings: {len(result.findings)}")
                file_console.print("-" * 40)

                for finding in result.findings:
                    location = f"{finding.location.start_line}:{finding.location.start_column}"
                    file_console.print(f"\n[{finding.severity.value.upper()}] {finding.title}")
                    file_console.print(f"Location: {location}")
                    file_console.print(f"Rule: {finding.rule_id}")
                    file_console.print(f"Message: {finding.message}")

                    if finding.remediation:
                        file_console.print(f"Remediation: {finding.remediation}")

                    if finding.code_snippet:
                        file_console.print("\nCode:")
                        file_console.print(finding.code_snippet)
                        file_console.print()

    def set_quiet(self, quiet: bool) -> None:
        """Set quiet mode"""
        self.quiet = quiet