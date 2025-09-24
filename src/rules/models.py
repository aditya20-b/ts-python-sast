"""
Data models for rules, patterns, and findings
"""

from typing import List, Dict, Any, Optional, Union
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    """Security finding severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PatternType(str, Enum):
    """Types of patterns that can be matched"""
    CALL = "call"
    ASSIGNMENT = "assignment"
    IMPORT = "import"
    STRING_LITERAL = "string_literal"
    REGEX = "regex"


class ArgumentCondition(BaseModel):
    """Condition for matching function arguments"""
    name: str = Field(..., description="Argument name (for keyword args)")
    equals: Optional[Union[str, bool, int, float]] = Field(None, description="Exact value match")
    contains: Optional[str] = Field(None, description="String contains check")
    regex: Optional[str] = Field(None, description="Regex pattern match")
    present: Optional[bool] = Field(None, description="Check if argument is present")


class CallPattern(BaseModel):
    """Pattern for matching function/method calls"""
    name: Optional[str] = Field(None, description="Exact function name")
    qualified_name: Optional[str] = Field(None, description="Fully qualified name (e.g., subprocess.run)")
    anyOf: Optional[List[str]] = Field(None, description="Match any of these names")
    module: Optional[str] = Field(None, description="Module the function belongs to")
    args: Optional[List[ArgumentCondition]] = Field(None, description="Argument conditions")


class Pattern(BaseModel):
    """Generic pattern matching configuration"""
    kind: PatternType = Field(..., description="Type of pattern to match")
    callee: Optional[CallPattern] = Field(None, description="Call pattern (for kind=call)")
    name: Optional[str] = Field(None, description="Simple name pattern")
    regex: Optional[str] = Field(None, description="Regex pattern")
    args: Optional[Dict[str, Any]] = Field(None, description="Additional arguments")


class Rule(BaseModel):
    """Security rule definition"""
    id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Human-readable rule title")
    severity: Severity = Field(..., description="Severity level")
    message: str = Field(..., description="Finding message")
    description: Optional[str] = Field(None, description="Detailed rule description")
    patterns: List[Pattern] = Field(..., description="Patterns to match")
    examples: Optional[Dict[str, str]] = Field(None, description="Good/bad examples")
    tags: Optional[List[str]] = Field(None, description="Rule tags")
    references: Optional[List[str]] = Field(None, description="External references")


class CodeLocation(BaseModel):
    """Location in source code"""
    file_path: str = Field(..., description="File path")
    start_line: int = Field(..., description="Start line number (1-based)")
    start_column: int = Field(..., description="Start column number (1-based)")
    end_line: int = Field(..., description="End line number (1-based)")
    end_column: int = Field(..., description="End column number (1-based)")
    start_byte: int = Field(..., description="Start byte offset")
    end_byte: int = Field(..., description="End byte offset")


class Finding(BaseModel):
    """Security finding result"""
    rule_id: str = Field(..., description="Rule that triggered this finding")
    title: str = Field(..., description="Finding title")
    severity: Severity = Field(..., description="Severity level")
    message: str = Field(..., description="Finding message")
    location: CodeLocation = Field(..., description="Location in source code")
    code_snippet: str = Field(..., description="Relevant code snippet")
    confidence: float = Field(default=1.0, description="Confidence score (0-1)")
    remediation: Optional[str] = Field(None, description="Suggested fix")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

    class Config:
        """Pydantic configuration"""
        json_encoders = {
            Severity: lambda v: v.value
        }


class ScanResult(BaseModel):
    """Results from a security scan"""
    file_path: str = Field(..., description="Scanned file path")
    findings: List[Finding] = Field(..., description="Security findings")
    scan_time_ms: float = Field(..., description="Scan duration in milliseconds")
    rules_applied: int = Field(..., description="Number of rules applied")
    errors: Optional[List[str]] = Field(None, description="Scan errors")

    @property
    def finding_count(self) -> int:
        """Total number of findings"""
        return len(self.findings)

    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Group findings by severity"""
        grouped = {severity: [] for severity in Severity}
        for finding in self.findings:
            grouped[finding.severity].append(finding)
        return grouped

    def has_findings(self, min_severity: Severity = Severity.LOW) -> bool:
        """Check if there are findings at or above minimum severity"""
        severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        min_index = severity_order.index(min_severity)

        for finding in self.findings:
            if severity_order.index(finding.severity) >= min_index:
                return True
        return False


class RuleSet(BaseModel):
    """Collection of security rules"""
    name: str = Field(..., description="Rule set name")
    version: str = Field(..., description="Rule set version")
    description: Optional[str] = Field(None, description="Rule set description")
    rules: List[Rule] = Field(..., description="Security rules")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """Get rule by ID"""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def get_rules_by_severity(self, severity: Severity) -> List[Rule]:
        """Get rules by severity level"""
        return [rule for rule in self.rules if rule.severity == severity]

    def get_rules_by_tag(self, tag: str) -> List[Rule]:
        """Get rules by tag"""
        return [rule for rule in self.rules if rule.tags and tag in rule.tags]