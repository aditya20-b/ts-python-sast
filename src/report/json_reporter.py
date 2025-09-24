"""
JSON reporter for machine-readable output
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..rules.models import ScanResult, Finding, Severity


class JSONReporter:
    """JSON output formatter for scan results"""

    def __init__(self, pretty: bool = True):
        self.pretty = pretty

    def export_results(self, results: List[ScanResult], output_file: str,
                      include_metadata: bool = True) -> None:
        """Export scan results to JSON file"""
        output_data = self._format_results(results, include_metadata)

        with open(output_file, 'w') as f:
            if self.pretty:
                json.dump(output_data, f, indent=2, default=self._json_serializer)
            else:
                json.dump(output_data, f, default=self._json_serializer)

    def format_results_string(self, results: List[ScanResult],
                            include_metadata: bool = True) -> str:
        """Format scan results as JSON string"""
        output_data = self._format_results(results, include_metadata)

        if self.pretty:
            return json.dumps(output_data, indent=2, default=self._json_serializer)
        else:
            return json.dumps(output_data, default=self._json_serializer)

    def _format_results(self, results: List[ScanResult],
                       include_metadata: bool = True) -> Dict[str, Any]:
        """Format scan results into JSON structure"""
        # Calculate summary statistics
        total_findings = sum(len(result.findings) for result in results)
        severity_counts = {severity.value: 0 for severity in Severity}

        for result in results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1

        # Build output structure
        output_data = {
            "scan_info": {
                "tool": "ts-sast",
                "version": "0.1.0",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "files_scanned": len(results),
                "total_findings": total_findings
            },
            "summary": {
                "findings_by_severity": severity_counts,
                "has_high_severity": (
                    severity_counts["high"] > 0 or
                    severity_counts["critical"] > 0
                )
            },
            "results": []
        }

        # Add detailed results
        for result in results:
            result_data = {
                "file": result.file_path,
                "finding_count": result.finding_count,
                "scan_time_ms": result.scan_time_ms,
                "rules_applied": result.rules_applied,
                "findings": []
            }

            # Add findings
            for finding in result.findings:
                finding_data = {
                    "rule_id": finding.rule_id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "message": finding.message,
                    "location": {
                        "file": finding.location.file_path,
                        "line": finding.location.start_line,
                        "column": finding.location.start_column,
                        "end_line": finding.location.end_line,
                        "end_column": finding.location.end_column,
                        "byte_offset": {
                            "start": finding.location.start_byte,
                            "end": finding.location.end_byte
                        }
                    },
                    "confidence": finding.confidence
                }

                # Add optional fields
                if finding.remediation:
                    finding_data["remediation"] = finding.remediation

                if finding.code_snippet:
                    finding_data["code_snippet"] = finding.code_snippet

                if include_metadata and finding.metadata:
                    finding_data["metadata"] = finding.metadata

                result_data["findings"].append(finding_data)

            # Add errors if any
            if result.errors:
                result_data["errors"] = result.errors

            output_data["results"].append(result_data)

        return output_data

    def export_summary_only(self, results: List[ScanResult], output_file: str) -> None:
        """Export only summary statistics to JSON"""
        total_findings = sum(len(result.findings) for result in results)
        severity_counts = {severity.value: 0 for severity in Severity}

        for result in results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1

        summary_data = {
            "scan_info": {
                "tool": "ts-sast",
                "version": "0.1.0",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "files_scanned": len(results),
                "total_findings": total_findings
            },
            "summary": {
                "findings_by_severity": severity_counts,
                "has_high_severity": (
                    severity_counts["high"] > 0 or
                    severity_counts["critical"] > 0
                ),
                "files_with_findings": len([r for r in results if r.findings]),
                "clean_files": len([r for r in results if not r.findings])
            }
        }

        with open(output_file, 'w') as f:
            if self.pretty:
                json.dump(summary_data, f, indent=2)
            else:
                json.dump(summary_data, f)

    def export_findings_by_rule(self, results: List[ScanResult], output_file: str) -> None:
        """Export findings grouped by rule ID"""
        findings_by_rule = {}

        for result in results:
            for finding in result.findings:
                rule_id = finding.rule_id
                if rule_id not in findings_by_rule:
                    findings_by_rule[rule_id] = {
                        "rule_id": rule_id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "count": 0,
                        "occurrences": []
                    }

                findings_by_rule[rule_id]["count"] += 1
                findings_by_rule[rule_id]["occurrences"].append({
                    "file": finding.location.file_path,
                    "line": finding.location.start_line,
                    "column": finding.location.start_column,
                    "message": finding.message
                })

        # Sort by severity and count
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_rules = sorted(
            findings_by_rule.values(),
            key=lambda x: (severity_order.get(x["severity"], 4), -x["count"])
        )

        output_data = {
            "scan_info": {
                "tool": "ts-sast",
                "version": "0.1.0",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "rules_triggered": len(sorted_rules),
            "findings_by_rule": sorted_rules
        }

        with open(output_file, 'w') as f:
            if self.pretty:
                json.dump(output_data, f, indent=2)
            else:
                json.dump(output_data, f)

    def _json_serializer(self, obj: Any) -> Any:
        """Custom JSON serializer for special types"""
        if isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        else:
            return str(obj)

    def validate_json_output(self, json_file: str) -> bool:
        """Validate that the output JSON file is well-formed"""
        try:
            with open(json_file, 'r') as f:
                json.load(f)
            return True
        except (json.JSONDecodeError, FileNotFoundError):
            return False

    def merge_results(self, json_files: List[str], output_file: str) -> None:
        """Merge multiple JSON result files into one"""
        merged_results = []
        scan_info = None

        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                if not scan_info:
                    scan_info = data.get("scan_info", {})

                merged_results.extend(data.get("results", []))

            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Error reading {json_file}: {e}")

        # Calculate merged statistics
        total_findings = sum(result.get("finding_count", 0) for result in merged_results)
        severity_counts = {severity.value: 0 for severity in Severity}

        for result in merged_results:
            for finding in result.get("findings", []):
                severity = finding.get("severity")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        merged_data = {
            "scan_info": {
                **scan_info,
                "files_scanned": len(merged_results),
                "total_findings": total_findings,
                "timestamp": datetime.utcnow().isoformat() + "Z"
            },
            "summary": {
                "findings_by_severity": severity_counts,
                "has_high_severity": (
                    severity_counts["high"] > 0 or
                    severity_counts["critical"] > 0
                )
            },
            "results": merged_results
        }

        with open(output_file, 'w') as f:
            if self.pretty:
                json.dump(merged_data, f, indent=2)
            else:
                json.dump(merged_data, f)