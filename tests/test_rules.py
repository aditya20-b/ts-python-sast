"""
Test cases for security rules
"""

import pytest
from pathlib import Path

from src.rules.engine import RuleEngine
from src.rules.models import Severity


class TestRuleEngine:
    """Test rule engine functionality"""

    def setup_method(self):
        """Set up test fixtures"""
        self.engine = RuleEngine()
        # Load rules from our rules directory
        rules_dir = Path(__file__).parent.parent / "rules" / "python"
        if rules_dir.exists():
            self.engine.load_rules_from_directory(str(rules_dir))

    def test_eval_detection(self):
        """Test detection of eval() usage"""
        code = '''
def dangerous_function():
    result = eval("1 + 1")
    return result
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.EVAL.USE"]
        assert len(findings) >= 1

    def test_subprocess_shell_detection(self):
        """Test detection of subprocess with shell=True"""
        code = '''
import subprocess
subprocess.run("ls -la", shell=True)
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.SUBPROCESS.SHELL"]
        assert len(findings) >= 1

    def test_os_system_detection(self):
        """Test detection of os.system()"""
        code = '''
import os
os.system("rm -rf /tmp/test")
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.OS.SYSTEM"]
        assert len(findings) >= 1

    def test_yaml_unsafe_detection(self):
        """Test detection of unsafe YAML loading"""
        code = '''
import yaml
data = yaml.load(user_input)
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.YAML.UNSAFE_LOAD"]
        assert len(findings) >= 1

    def test_pickle_detection(self):
        """Test detection of pickle usage"""
        code = '''
import pickle
data = pickle.loads(untrusted_data)
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.PICKLE.LOAD"]
        assert len(findings) >= 1

    def test_weak_hash_detection(self):
        """Test detection of weak hash algorithms"""
        code = '''
import hashlib
hash_value = hashlib.md5(data).hexdigest()
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.HASH.WEAK"]
        assert len(findings) >= 1

    def test_requests_noverify_detection(self):
        """Test detection of disabled SSL verification"""
        code = '''
import requests
response = requests.get(url, verify=False)
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.REQUESTS.VERIFY_FALSE"]
        assert len(findings) >= 1

    def test_hardcoded_secrets_detection(self):
        """Test detection of hardcoded secrets"""
        code = '''
API_KEY = "sk-1234567890abcdefghijklmnop"
PASSWORD = "super_secret_password"
'''
        result = self.engine.scan_string(code)
        findings = [f for f in result.findings if f.rule_id == "PY.SECRET.HARDCODED"]
        assert len(findings) >= 1

    def test_safe_code_no_findings(self):
        """Test that safe code produces no findings"""
        code = '''
import subprocess
import yaml
import json
import hashlib
import ast

# Safe alternatives
result = ast.literal_eval("1 + 1")
subprocess.run(["ls", "-la"])
data = yaml.safe_load(yaml_string)
obj = json.loads(json_string)
hash_val = hashlib.sha256(data).hexdigest()
'''
        result = self.engine.scan_string(code)
        # Should have minimal or no findings for safe code
        assert len(result.findings) == 0

    def test_severity_filtering(self):
        """Test filtering by severity level"""
        code = '''
import hashlib
# This should be medium severity
hash_val = hashlib.md5(data).hexdigest()

# This should be high severity
result = eval(user_input)
'''
        # Test with different severity filters
        result_all = self.engine.scan_string(code, min_severity=Severity.LOW)
        result_medium = self.engine.scan_string(code, min_severity=Severity.MEDIUM)
        result_high = self.engine.scan_string(code, min_severity=Severity.HIGH)

        # Should have more findings with lower threshold
        assert len(result_all.findings) >= len(result_medium.findings)
        assert len(result_medium.findings) >= len(result_high.findings)

    def test_rule_id_filtering(self):
        """Test filtering by specific rule IDs"""
        code = '''
import subprocess
import os
subprocess.run("ls", shell=True)
os.system("pwd")
'''
        # Test with specific rule
        result = self.engine.scan_string(code, rule_ids=["PY.SUBPROCESS.SHELL"])

        # Should only have subprocess findings
        subprocess_findings = [f for f in result.findings if f.rule_id == "PY.SUBPROCESS.SHELL"]
        os_system_findings = [f for f in result.findings if f.rule_id == "PY.OS.SYSTEM"]

        assert len(subprocess_findings) >= 1
        assert len(os_system_findings) == 0


class TestRuleDefinitions:
    """Test individual rule definitions"""

    def test_rule_completeness(self):
        """Test that all rules have required fields"""
        engine = RuleEngine()
        rules_dir = Path(__file__).parent.parent / "rules" / "python"

        if rules_dir.exists():
            engine.load_rules_from_directory(str(rules_dir))

        for rule in engine.rules:
            assert rule.id is not None
            assert rule.title is not None
            assert rule.message is not None
            assert rule.severity is not None
            assert len(rule.patterns) > 0

    def test_rule_patterns(self):
        """Test that rule patterns are well-formed"""
        engine = RuleEngine()
        rules_dir = Path(__file__).parent.parent / "rules" / "python"

        if rules_dir.exists():
            engine.load_rules_from_directory(str(rules_dir))

        for rule in engine.rules:
            for pattern in rule.patterns:
                assert pattern.kind is not None
                # Patterns should have either a callee or name/regex
                if pattern.kind.value == "call":
                    assert pattern.callee is not None or pattern.name is not None


if __name__ == "__main__":
    pytest.main([__file__])