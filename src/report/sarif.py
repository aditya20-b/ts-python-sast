"""
SARIF (Static Analysis Results Interchange Format) 2.1.0 reporter
"""

import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..rules.models import ScanResult, Finding, Severity


class SARIFReporter:
    """SARIF 2.1.0 compliant reporter for scan results"""

    def __init__(self):
        self.sarif_version = "2.1.0"
        self.tool_name = "ts-sast"
        self.tool_version = "0.1.0"

    def export_sarif(self, results: List[ScanResult], output_file: str,
                    rules_info: Optional[Dict[str, Any]] = None) -> None:
        """Export scan results to SARIF format"""
        sarif_data = self._create_sarif_document(results, rules_info)

        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)

    def create_sarif_string(self, results: List[ScanResult],
                           rules_info: Optional[Dict[str, Any]] = None) -> str:
        """Create SARIF document as string"""
        sarif_data = self._create_sarif_document(results, rules_info)
        return json.dumps(sarif_data, indent=2)

    def _create_sarif_document(self, results: List[ScanResult],
                             rules_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create complete SARIF document structure"""
        # Collect all unique rules from findings
        rules_used = set()
        all_findings = []

        for result in results:
            all_findings.extend(result.findings)
            for finding in result.findings:
                rules_used.add(finding.rule_id)

        # Create SARIF document
        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": self.sarif_version,
            "runs": [
                {
                    "tool": self._create_tool_component(rules_used, rules_info),
                    "invocations": [self._create_invocation(results)],
                    "results": self._create_results(all_findings),
                    "artifacts": self._create_artifacts(results)
                }
            ]
        }

        return sarif_doc

    def _create_tool_component(self, rules_used: set,
                             rules_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create tool component with driver information"""
        driver = {
            "name": self.tool_name,
            "version": self.tool_version,
            "fullName": "Tree-sitter Static Analysis Security Testing",
            "informationUri": "https://github.com/yourusername/ts-sast",
            "rules": []
        }

        # Add rule definitions
        for rule_id in rules_used:
            rule_def = self._create_rule_definition(rule_id, rules_info)
            driver["rules"].append(rule_def)

        return {"driver": driver}

    def _create_rule_definition(self, rule_id: str,
                              rules_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create rule definition for SARIF"""
        # Basic rule definition
        rule_def = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {
                "text": f"Security rule {rule_id}"
            },
            "fullDescription": {
                "text": f"Security rule {rule_id}"
            },
            "defaultConfiguration": {
                "level": "warning"
            },
            "properties": {
                "tags": ["security"]
            }
        }

        # Enhance with actual rule information if available
        if rules_info and rule_id in rules_info:
            rule_info = rules_info[rule_id]

            rule_def["shortDescription"]["text"] = rule_info.get("title", rule_def["shortDescription"]["text"])
            rule_def["fullDescription"]["text"] = rule_info.get("description", rule_info.get("message", rule_def["fullDescription"]["text"]))

            # Map severity to SARIF level
            severity = rule_info.get("severity", "medium")
            rule_def["defaultConfiguration"]["level"] = self._severity_to_sarif_level(severity)

            # Add tags
            if "tags" in rule_info:
                rule_def["properties"]["tags"].extend(rule_info["tags"])

            # Add help information
            if "references" in rule_info:
                rule_def["helpUri"] = rule_info["references"][0]  # Use first reference

        return rule_def

    def _create_invocation(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Create invocation information"""
        total_scan_time = sum(result.scan_time_ms for result in results)

        return {
            "executionSuccessful": True,
            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
            "endTimeUtc": datetime.utcnow().isoformat() + "Z",
            "workingDirectory": {
                "uri": Path.cwd().as_uri()
            },
            "properties": {
                "filesScanned": len(results),
                "totalScanTimeMs": total_scan_time
            }
        }

    def _create_results(self, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Create SARIF results from findings"""
        sarif_results = []

        for finding in findings:
            result = {
                "ruleId": finding.rule_id,
                "ruleIndex": 0,  # Would need to map to actual rule index
                "message": {
                    "text": finding.message
                },
                "level": self._severity_to_sarif_level(finding.severity.value),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": self._path_to_uri(finding.location.file_path)
                            },
                            "region": {
                                "startLine": finding.location.start_line,
                                "startColumn": finding.location.start_column,
                                "endLine": finding.location.end_line,
                                "endColumn": finding.location.end_column,
                                "charOffset": finding.location.start_byte,
                                "charLength": finding.location.end_byte - finding.location.start_byte
                            }
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence
                }
            }

            # Add code snippet if available
            if finding.code_snippet:
                result["locations"][0]["physicalLocation"]["contextRegion"] = {
                    "snippet": {
                        "text": finding.code_snippet
                    }
                }

            # Add remediation information
            if finding.remediation:
                result["fixes"] = [
                    {
                        "description": {
                            "text": finding.remediation
                        }
                    }
                ]

            # Add metadata
            if finding.metadata:
                result["properties"].update(finding.metadata)

            sarif_results.append(result)

        return sarif_results

    def _create_artifacts(self, results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Create artifacts (files) information"""
        artifacts = []

        for result in results:
            artifact = {
                "location": {
                    "uri": self._path_to_uri(result.file_path)
                },
                "properties": {
                    "scanTimeMs": result.scan_time_ms,
                    "rulesApplied": result.rules_applied,
                    "findingCount": result.finding_count
                }
            }

            # Add errors if any
            if result.errors:
                artifact["properties"]["errors"] = result.errors

            artifacts.append(artifact)

        return artifacts

    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level"""
        severity_mapping = {
            "low": "note",
            "medium": "warning",
            "high": "error",
            "critical": "error"
        }
        return severity_mapping.get(severity.lower(), "warning")

    def _path_to_uri(self, file_path: str) -> str:
        """Convert file path to URI"""
        # Convert to absolute path and then to URI
        abs_path = Path(file_path).resolve()
        return abs_path.as_uri()

    def validate_sarif(self, sarif_file: str) -> bool:
        """Basic validation of SARIF file structure"""
        try:
            with open(sarif_file, 'r') as f:
                data = json.load(f)

            # Check required top-level fields
            required_fields = ["$schema", "version", "runs"]
            for field in required_fields:
                if field not in data:
                    return False

            # Check runs structure
            runs = data.get("runs", [])
            if not runs:
                return False

            for run in runs:
                if "tool" not in run or "results" not in run:
                    return False

            return True

        except (json.JSONDecodeError, FileNotFoundError):
            return False

    def create_empty_sarif(self) -> Dict[str, Any]:
        """Create empty SARIF document for when no findings are found"""
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": self.sarif_version,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": self.tool_name,
                            "version": self.tool_version,
                            "fullName": "Tree-sitter Static Analysis Security Testing",
                            "informationUri": "https://github.com/yourusername/ts-sast",
                            "rules": []
                        }
                    },
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                            "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                        }
                    ],
                    "results": [],
                    "artifacts": []
                }
            ]
        }