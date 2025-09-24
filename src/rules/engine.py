"""
Rule engine for loading and executing security rules
"""

import os
import time
from pathlib import Path
from typing import List, Dict, Optional, Any, Union
import yaml
from pydantic import ValidationError

from ..parsing.ast_utils import ASTNode
from ..parsing.parser import PythonParser
from .models import Rule, Finding, ScanResult, CodeLocation, Severity, RuleSet
from .matcher import PatternMatcher


class RuleEngine:
    """Engine for loading and executing security rules"""

    def __init__(self, rules_directory: Optional[str] = None):
        self.rules: List[Rule] = []
        self.matcher = PatternMatcher()
        self.parser = PythonParser()

        if rules_directory:
            self.load_rules_from_directory(rules_directory)

    def load_rules_from_directory(self, directory: str) -> int:
        """Load all YAML rule files from a directory"""
        rules_path = Path(directory)
        if not rules_path.exists():
            raise FileNotFoundError(f"Rules directory not found: {directory}")

        loaded_count = 0
        for yaml_file in rules_path.glob("**/*.yaml"):
            try:
                count = self.load_rules_from_file(str(yaml_file))
                loaded_count += count
            except Exception as e:
                print(f"Error loading rules from {yaml_file}: {e}")

        return loaded_count

    def load_rules_from_file(self, file_path: str) -> int:
        """Load rules from a single YAML file"""
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)

        loaded_count = 0

        # Handle single rule or rule set
        if isinstance(data, dict):
            if 'rules' in data:
                # Rule set format
                try:
                    rule_set = RuleSet(**data)
                    self.rules.extend(rule_set.rules)
                    loaded_count = len(rule_set.rules)
                except ValidationError as e:
                    print(f"Invalid rule set format in {file_path}: {e}")
            else:
                # Single rule format
                try:
                    rule = Rule(**data)
                    self.rules.append(rule)
                    loaded_count = 1
                except ValidationError as e:
                    print(f"Invalid rule format in {file_path}: {e}")

        elif isinstance(data, list):
            # List of rules
            for rule_data in data:
                try:
                    rule = Rule(**rule_data)
                    self.rules.append(rule)
                    loaded_count += 1
                except ValidationError as e:
                    print(f"Invalid rule in {file_path}: {e}")

        return loaded_count

    def add_rule(self, rule: Rule) -> None:
        """Add a single rule to the engine"""
        self.rules.append(rule)

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by its ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def scan_file(self, file_path: str,
                  rule_ids: Optional[List[str]] = None,
                  min_severity: Optional[Severity] = None) -> ScanResult:
        """Scan a single file with loaded rules"""
        start_time = time.time()

        # Parse the file
        ast = self.parser.parse_file(file_path)
        if not ast:
            return ScanResult(
                file_path=file_path,
                findings=[],
                scan_time_ms=0,
                rules_applied=0,
                errors=[f"Failed to parse file: {file_path}"]
            )

        # Filter rules based on criteria
        active_rules = self._filter_rules(rule_ids, min_severity)

        # Apply rules and collect findings
        findings = []
        errors = []

        for rule in active_rules:
            try:
                rule_findings = self._apply_rule(ast, rule, file_path)
                findings.extend(rule_findings)
            except Exception as e:
                errors.append(f"Error applying rule {rule.id}: {e}")

        scan_time = (time.time() - start_time) * 1000

        return ScanResult(
            file_path=file_path,
            findings=findings,
            scan_time_ms=scan_time,
            rules_applied=len(active_rules),
            errors=errors if errors else None
        )

    def scan_string(self, code: str, file_path: str = "<string>",
                   rule_ids: Optional[List[str]] = None,
                   min_severity: Optional[Severity] = None) -> ScanResult:
        """Scan code from a string"""
        start_time = time.time()

        # Parse the code
        ast = self.parser.parse_string(code)
        if not ast:
            return ScanResult(
                file_path=file_path,
                findings=[],
                scan_time_ms=0,
                rules_applied=0,
                errors=["Failed to parse code string"]
            )

        # Filter rules and apply them
        active_rules = self._filter_rules(rule_ids, min_severity)
        findings = []
        errors = []

        for rule in active_rules:
            try:
                rule_findings = self._apply_rule(ast, rule, file_path)
                findings.extend(rule_findings)
            except Exception as e:
                errors.append(f"Error applying rule {rule.id}: {e}")

        scan_time = (time.time() - start_time) * 1000

        return ScanResult(
            file_path=file_path,
            findings=findings,
            scan_time_ms=scan_time,
            rules_applied=len(active_rules),
            errors=errors if errors else None
        )

    def _filter_rules(self, rule_ids: Optional[List[str]] = None,
                     min_severity: Optional[Severity] = None) -> List[Rule]:
        """Filter rules based on criteria"""
        filtered_rules = self.rules

        # Filter by rule IDs
        if rule_ids:
            filtered_rules = [rule for rule in filtered_rules if rule.id in rule_ids]

        # Filter by minimum severity
        if min_severity:
            severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            min_index = severity_order.index(min_severity)
            filtered_rules = [
                rule for rule in filtered_rules
                if severity_order.index(rule.severity) >= min_index
            ]

        return filtered_rules

    def _apply_rule(self, ast: ASTNode, rule: Rule, file_path: str) -> List[Finding]:
        """Apply a single rule to an AST and return findings"""
        findings = []

        # Find all nodes that match any of the rule's patterns
        for pattern in rule.patterns:
            matches = self.matcher.find_matches(ast, [pattern])

            for match in matches:
                finding = self._create_finding(ast, match, rule, file_path)
                findings.append(finding)

        return findings

    def _create_finding(self, ast: ASTNode, node: ASTNode, rule: Rule, file_path: str) -> Finding:
        """Create a Finding object from a matched node"""
        # Extract code snippet with context
        code_snippet = self.parser.extract_code_snippet(ast, node, context_lines=2)

        # Create location info
        start_line, start_col = node.start_point
        end_line, end_col = node.end_point

        location = CodeLocation(
            file_path=file_path,
            start_line=start_line + 1,  # Convert to 1-based
            start_column=start_col + 1,
            end_line=end_line + 1,
            end_column=end_col + 1,
            start_byte=node.start_byte,
            end_byte=node.end_byte
        )

        # Generate remediation suggestion
        remediation = self._generate_remediation(rule, node)

        return Finding(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            message=rule.message,
            location=location,
            code_snippet=code_snippet,
            remediation=remediation,
            metadata={
                'node_type': node.type,
                'node_text': node.text[:100],  # Truncate for metadata
                'rule_tags': rule.tags or []
            }
        )

    def _generate_remediation(self, rule: Rule, node: ASTNode) -> Optional[str]:
        """Generate remediation suggestion based on rule and node"""
        # Use examples from rule if available
        if rule.examples and 'good' in rule.examples:
            return f"Consider using: {rule.examples['good']}"

        # Basic remediation based on rule ID patterns
        if 'SUBPROCESS.SHELL' in rule.id:
            return "Use subprocess with a list of arguments instead of shell=True"
        elif 'EVAL' in rule.id:
            return "Avoid using eval(). Consider safer alternatives like ast.literal_eval()"
        elif 'PICKLE' in rule.id:
            return "Use JSON or other safe serialization formats instead of pickle"
        elif 'YAML.UNSAFE' in rule.id:
            return "Use yaml.safe_load() instead of yaml.load()"

        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about loaded rules"""
        if not self.rules:
            return {'total_rules': 0}

        severity_counts = {}
        for severity in Severity:
            severity_counts[severity.value] = len([r for r in self.rules if r.severity == severity])

        tag_counts = {}
        for rule in self.rules:
            if rule.tags:
                for tag in rule.tags:
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            'total_rules': len(self.rules),
            'severity_counts': severity_counts,
            'tag_counts': tag_counts,
            'rule_ids': [rule.id for rule in self.rules]
        }