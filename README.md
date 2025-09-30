# TS-SAST: Tree-sitter Static Analysis Security Testing

A lightweight static analysis security testing tool built with tree-sitter for Python code analysis.

## Features

- **Fast and Lightweight**: Built with tree-sitter for efficient parsing
- **Configurable Rules**: YAML-based security rules that are easy to extend
- **Multiple Output Formats**: Console, JSON, and SARIF 2.1.0 support
- **CI/CD Ready**: Integrates seamlessly with continuous integration pipelines
- **Zero Runtime Dependencies**: Self-contained security scanning


## Workflow
1. CLI Layer (src/cli.py)
    - Entry point using Typer framework
    - Commands: scan, rules, validate, demo
    - Handles argument parsing and orchestrates the scanning workflow
2. Rule Engine (src/rules/engine.py)
    - Central orchestrator that manages rules and scanning
    - Loads YAML rule definitions from directories
    - Applies rules to parsed AST and collects findings
3. Parsing Layer (src/parsing/parser.py)
    - Tree-sitter Python parser wrapper
    - AST caching for performance
    - Code extraction and analysis utilities
4. Pattern Matching (src/rules/matcher.py)
    - Matches AST nodes against rule patterns
    - Supports various pattern types: calls, assignments, imports,
  string literals, regex
    - Argument analysis and validation
5. Reporting (src/report/)
    - Multiple output formats: Console, JSON, SARIF
    - Rich terminal output with syntax highlighting
    - CI/CD integration support

## Quick Start

### Installation

```bash
pip install -e .
```

### Basic Usage
```python
ts-scan = python -m src.cli
```

```bash
# Scan a single file
ts-sast scan vulnerable.py

# Scan a directory
ts-sast scan src/

# Output to JSON
ts-sast scan src/ --format json --output results.json

# Output to SARIF for CI integration
ts-sast scan src/ --format sarif --output results.sarif

# Show only high severity issues
ts-sast scan src/ --severity high
```

### Generate Demo Files

```bash
# Create example vulnerable and safe files
ts-sast demo --output demo/

# Scan the vulnerable demo file
ts-sast scan demo/vulnerable.py
```

## Security Rules

TS-SAST includes built-in rules for common Python security issues:

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `PY.EVAL.USE` | Dangerous use of `eval()` or `exec()` | High |
| `PY.SUBPROCESS.SHELL` | Subprocess called with `shell=True` | High |
| `PY.OS.SYSTEM` | Use of `os.system()` | High |
| `PY.YAML.UNSAFE_LOAD` | Unsafe YAML loading | High |
| `PY.PICKLE.LOAD` | Unsafe pickle deserialization | High |
| `PY.HASH.WEAK` | Weak cryptographic hash function | Medium |
| `PY.REQUESTS.VERIFY_FALSE` | Disabled SSL certificate verification | Medium |
| `PY.SECRET.HARDCODED` | Potential hardcoded secret | Medium |

### List Available Rules

```bash
# Show all rules
ts-sast rules

# Filter by severity
ts-sast rules --severity high

# Show as JSON
ts-sast rules --format json
```

### Validate Rules

```bash
# Validate rule files
ts-sast validate rules/python/
```

## Output Formats

### Console Output
Rich terminal output with syntax highlighting and colored severity indicators.

### JSON Output
Machine-readable format for integration with other tools:

```json
{
  "scan_info": {
    "tool": "ts-sast",
    "version": "0.1.0",
    "timestamp": "2024-01-01T12:00:00Z",
    "files_scanned": 1,
    "total_findings": 2
  },
  "results": [
    {
      "file": "vulnerable.py",
      "findings": [
        {
          "rule_id": "PY.EVAL.USE",
          "title": "Dangerous use of eval() or exec()",
          "severity": "high",
          "message": "Avoid using eval() or exec() with untrusted input",
          "location": {
            "line": 10,
            "column": 12
          }
        }
      ]
    }
  ]
}
```

### SARIF Output
Standard format for static analysis tools, supported by GitHub and other platforms.

## Configuration

Create a `.ts-sast.yml` file in your project root:

```yaml
rules:
  - rules/python/*.yaml
entries:
  - main
  - handler
sources:
  - input()
  - flask.request.args
sinks:
  - subprocess.run
  - os.system
ignore:
  - "test_*.py"
  - "tests/"
```

## CLI Commands

### `scan`
Scan files for security issues.

```bash
ts-sast scan [PATH] [OPTIONS]
```

**Options:**
- `--rules, -r`: Rules directory (default: rules/python)
- `--format, -f`: Output format (console, json, sarif, text)
- `--output, -o`: Output file
- `--severity, -s`: Minimum severity (low, medium, high, critical)
- `--quiet, -q`: Suppress console output
- `--show-code/--no-code`: Show/hide code snippets
- `--rule`: Specific rules to run
- `--exclude`: Rules to exclude
- `--color/--no-color`: Enable/disable colored output

### `rules`
List available security rules.

```bash
ts-sast rules [OPTIONS]
```

**Options:**
- `--rules-dir, -r`: Rules directory
- `--format, -f`: Output format (table, json, ids)
- `--severity, -s`: Filter by severity
- `--tag, -t`: Filter by tag

### `validate`
Validate rule files.

```bash
ts-sast validate [RULES_DIR] [OPTIONS]
```

**Options:**
- `--verbose, -v`: Show detailed validation info

### `demo`
Generate demo files with security issues.

```bash
ts-sast demo [OPTIONS]
```

**Options:**
- `--output, -o`: Output directory (default: demo)

### `graph`
Generate call graph for Python file.

```bash
ts-sast graph [FILE] [OPTIONS]
```

**Options:**
- `--format, -f`: Output format (dot, json, graphml, cytoscape)
- `--output, -o`: Output file (default: auto-generated)
- `--layout, -l`: Layout hint (hierarchical, force_directed, circular, tree)
- `--entry`: Entry point functions (can be repeated)
- `--reachable-only`: Only include reachable functions
- `--include-external`: Include external function calls
- `--cluster`: Group functions by file/module
- `--quiet, -q`: Suppress console output

### `analyze`
Perform advanced call graph analysis.

```bash
ts-sast analyze [FILE] [OPTIONS]
```

**Options:**
- `--entry`: Entry point functions
- `--cycles`: Find cycles in call graph
- `--dead-code`: Find potentially dead code
- `--critical N`: Show top N critical functions
- `--impact FUNC`: Analyze impact of removing specific function
- `--format`: Output format (table, json)

## Exit Codes

- `0`: No security issues found
- `1`: High or critical severity issues found
- `2`: Medium or low severity issues found

## Development

### Project Structure

```
ts-sast/
├── src/
│   ├── parsing/          # Tree-sitter parsing
│   ├── rules/            # Rule engine
│   ├── graph/            # Call graph analysis (future)
│   ├── taint/            # Taint analysis (future)
│   ├── report/           # Output formatters
│   └── cli.py            # Command-line interface
├── rules/python/         # Security rule definitions
├── tests/                # Test suite
├── examples/             # Example files
└── pyproject.toml
```

### Running Tests

```bash
pytest tests/
```

### Adding New Rules

Create a YAML file in `rules/python/`:

```yaml
id: PY.CUSTOM.RULE
title: Custom security rule
severity: medium
description: Detailed description of the security issue
message: Short message for findings
patterns:
  - kind: call
    callee:
      name: dangerous_function
examples:
  bad: dangerous_function(user_input)
  good: safe_function(user_input)
tags:
  - custom
  - security
references:
  - "https://example.com/security-guide"
```

## Phase 2: Call Graph Analysis ✅

**Completed Features:**
- **Symbol Table Builder**: Discovers all functions, methods, and their metadata
- **Call Graph Construction**: Maps function call relationships with confidence scoring
- **Reachability Analysis**: Identifies reachable functions from entry points
- **Multiple Export Formats**: DOT (Graphviz), JSON, GraphML, Cytoscape.js
- **Advanced Analysis**: Dead code detection, cycle detection, centrality analysis
- **CLI Integration**: New `graph` and `analyze` commands
- **Web Viewer**: Interactive visualization with Cytoscape.js

**Usage Examples:**

```bash
# Generate DOT graph for Graphviz visualization
ts-sast graph mycode.py --format dot --output callgraph.dot

# Interactive analysis with statistics
ts-sast analyze mycode.py --cycles --dead-code --critical 5

# JSON export with external calls
ts-sast graph mycode.py --format json --include-external
```

## Roadmap

### Phase 3: Taint Analysis (Next)
- Source-to-sink data flow tracking
- Intra-procedural taint propagation
- Limited inter-procedural analysis

### Future Enhancements
- Support for more languages (JavaScript, Go, Rust)
- Framework-specific rules (Django, Flask, FastAPI)
- IDE integration
- GitHub Action for CI/CD

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security

If you find security issues in ts-sast itself, please report them responsibly by emailing [security contact].

## Acknowledgments

- Built with [tree-sitter](https://tree-sitter.github.io/)
- Inspired by semgrep, bandit, and other static analysis tools
- SARIF format support for CI/CD integration