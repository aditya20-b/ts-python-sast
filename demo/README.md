# TS-SAST Demo Files

This directory contains comprehensive, real-world demo files that showcase various security vulnerabilities and their secure alternatives. These examples are designed to help developers understand common security pitfalls and learn secure coding practices.

## Demo Files Overview

### 1. `vulnerable_web_app.py`
**Realistic Flask web application with common vulnerabilities**

**Vulnerabilities demonstrated:**
- SQL injection in login and search functionality
- Command injection via subprocess and os.system
- Server-Side Template Injection (SSTI)
- Hardcoded secrets and API keys
- Unsafe YAML/pickle deserialization
- Disabled SSL certificate verification
- Weak cryptographic hashing (MD5, SHA1)
- Path traversal in file upload
- Code injection via eval()

**Real-world context:** Simulates a typical web application with user authentication, file upload, search, and API proxy functionality.

### 2. `vulnerable_data_processor.py`
**Data processing system with ETL and analytics vulnerabilities**

**Vulnerabilities demonstrated:**
- Unsafe pickle deserialization in data loading
- Command injection in archive extraction
- SQL injection in dynamic query building
- Code execution via eval() in data transformations
- Hardcoded AWS credentials and database passwords
- Shell command execution with user input
- Weak hashing for data integrity

**Real-world context:** Represents data science pipelines, ETL systems, and analytics platforms commonly found in enterprise environments.

### 3. `vulnerable_devops_automation.py`
**DevOps automation script with infrastructure management issues**

**Vulnerabilities demonstrated:**
- Hardcoded cloud provider credentials (AWS, Azure, GCP)
- Command injection in Kubernetes deployments
- Shell execution in Terraform/Ansible automation
- Unsafe YAML processing in configuration
- SSH command injection in monitoring
- Exposed secrets in environment variables
- Weak hashing in configuration management

**Real-world context:** Simulates CI/CD pipelines, infrastructure as code, deployment automation, and monitoring systems.

### 4. `secure_alternatives.py`
**Secure implementation demonstrating best practices**

**Security practices demonstrated:**
- Environment variable configuration management
- Parameterized SQL queries
- Safe subprocess execution with argument lists
- Strong cryptographic hashing (SHA-256, PBKDF2)
- SSL certificate verification
- Input validation and sanitization
- Safe YAML loading with yaml.safe_load()
- JSON serialization instead of pickle
- Secure random number generation
- Proper error handling and logging

## Running the Demos

### Scan for vulnerabilities:

```bash
# Scan individual files
ts-sast scan demo/vulnerable_web_app.py
ts-sast scan demo/vulnerable_data_processor.py
ts-sast scan demo/vulnerable_devops_automation.py

# Scan entire demo directory
ts-sast scan demo/ --format json --output demo_results.json

# Show only high severity issues
ts-sast scan demo/ --severity high

# Export to SARIF for CI/CD integration
ts-sast scan demo/ --format sarif --output demo_results.sarif
```

### Compare with secure alternatives:

```bash
# Scan secure implementation (should find minimal/no issues)
ts-sast scan demo/secure_alternatives.py --show-code
```

### Generate call graphs:

```bash
# Generate call graph for complex applications
ts-sast graph demo/vulnerable_web_app.py --format dot --output webapp_callgraph.dot
ts-sast graph demo/vulnerable_data_processor.py --format json --include-external

# Analyze for dead code and critical functions
ts-sast analyze demo/vulnerable_devops_automation.py --dead-code --critical 5
```

## Educational Value

### For Security Teams:
- **Realistic attack vectors:** Examples based on actual vulnerabilities found in production systems
- **Context-aware scanning:** Vulnerabilities shown in realistic application contexts
- **Remediation guidance:** Each vulnerable pattern paired with secure alternative

### For Developers:
- **Common pitfalls:** Demonstrates mistakes developers frequently make
- **Secure alternatives:** Shows the correct way to implement each functionality
- **Best practices:** Covers authentication, data handling, cryptography, and system operations

### for DevOps/SRE:
- **Infrastructure security:** Focus on deployment and automation security
- **Configuration management:** Secure handling of secrets and configurations
- **Monitoring security:** Safe implementation of observability tools

## Vulnerability Categories Covered

| Category | Count | Examples |
|----------|--------|-----------|
| **Code Injection** | 15+ | `eval()`, `exec()`, template injection |
| **Command Injection** | 20+ | `subprocess.run(shell=True)`, `os.system()` |
| **Hardcoded Secrets** | 25+ | API keys, passwords, tokens |
| **Unsafe Deserialization** | 8+ | `pickle.load()`, `yaml.load()` |
| **Weak Cryptography** | 6+ | MD5, SHA1, weak random generation |
| **SSL/TLS Issues** | 5+ | `verify=False` in requests |
| **SQL Injection** | 4+ | Dynamic query building |
| **Path Traversal** | 3+ | Unsanitized file paths |

## Integration with CI/CD

These demo files are designed to integrate seamlessly with CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install ts-sast
        run: pip install -e .
      - name: Run security scan
        run: ts-sast scan demo/ --format sarif --output results.sarif
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

## Customization

### Adding New Vulnerability Patterns:

1. **Extend existing files:** Add new functions demonstrating additional vulnerability types
2. **Create new demo files:** Focus on specific domains (mobile, IoT, blockchain, etc.)
3. **Update rules:** Ensure TS-SAST rules cover new vulnerability patterns

### Creating Domain-Specific Demos:

- **Financial applications:** PCI DSS compliance issues
- **Healthcare systems:** HIPAA privacy violations
- **IoT devices:** Embedded system vulnerabilities
- **Microservices:** Container and orchestration security

## Learning Path

1. **Start with basic patterns:** Review `vulnerable.py` and `secure.py`
2. **Explore web security:** Analyze `vulnerable_web_app.py`
3. **Understand data security:** Study `vulnerable_data_processor.py`
4. **Learn infrastructure security:** Examine `vulnerable_devops_automation.py`
5. **Master secure practices:** Implement patterns from `secure_alternatives.py`

## Contributing

To add new demo content:

1. **Identify vulnerability class:** Focus on real-world, high-impact issues
2. **Create realistic context:** Embed vulnerabilities in believable application scenarios
3. **Provide secure alternatives:** Always show the correct implementation
4. **Add comprehensive comments:** Explain why each pattern is dangerous
5. **Test with TS-SAST:** Ensure new patterns are detected by existing rules

---

**Note:** These demo files contain intentional security vulnerabilities for educational purposes. Never deploy this code in production environments. Use only for learning and testing security tools.