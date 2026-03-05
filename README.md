# MCP Security Scanner

A static analysis tool that scans MCP (Model Context Protocol) server source code for 10 vulnerability classes that traditional SAST tools miss entirely -- plus an agentic investigation layer that uses Claude via AWS Bedrock to reason over findings and produce prioritized attack narratives.

## Detected Vulnerabilities

| # | Rule ID | Severity | Description |
|---|---------|----------|-------------|
| 1 | prompt-injection | HIGH | Resources reflecting unsanitized input into LLM context |
| 2 | tool-poisoning | CRITICAL | Coercive LLM instructions hidden in tool docstrings |
| 3 | excessive-permissions | HIGH | Path traversal via unrestricted open()/os.path.exists() |
| 4 | rug-pull | CRITICAL | Runtime mutation of tool `__doc__` after installation |
| 5 | tool-shadowing | HIGH | Duplicate tool names or cross-tool resource references |
| 6 | indirect-prompt-injection | HIGH | User content passed through to LLM context unsanitized |
| 7 | token-leakage | CRITICAL | Secrets interpolated into tool return values |
| 8 | code-execution | CRITICAL | User input flowing to subprocess/eval/exec sinks |
| 9 | command-injection | CRITICAL | Shell commands built from f-string interpolation |
| 10 | multi-vector | CRITICAL | 3+ distinct vulnerabilities in a single server file |

## Installation

```bash
pip install -r requirements.txt
```

Requires Python 3.10+. The `investigate` command additionally requires AWS credentials configured for Bedrock access in `us-east-1`.

## Usage

### Static Scan

```bash
# Scan a directory
python -m mcp_scanner scan /path/to/mcp/server

# JSON output
python -m mcp_scanner scan /path/to/server --format json --output report.json

# Filter by minimum severity
python -m mcp_scanner scan /path/to/server --severity medium

# Verbose logging
python -m mcp_scanner -v scan /path/to/server
```

### Agentic Investigation

```bash
# Investigate findings with a Claude agent via Bedrock
python -m mcp_scanner investigate /path/to/mcp/server

# Save the attack narrative to a file
python -m mcp_scanner investigate /path/to/server --output narrative.md

# Control which findings the agent sees
python -m mcp_scanner investigate /path/to/server --severity critical

# Limit agent iterations
python -m mcp_scanner investigate /path/to/server --max-iterations 10

# Use a different Bedrock model or region
python -m mcp_scanner investigate /path/to/server --model us.anthropic.claude-sonnet-4-20250514-v1:0 --region us-east-1
```

The `investigate` command runs the static scanner first, then feeds CRITICAL and HIGH findings into a Claude agent that iteratively calls investigation tools to trace taint paths, inspect function bodies, and discover attack chains. The output is a prioritized attack narrative, not a flat finding list.

### CLI Reference

#### `scan` command

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal` or `json` |
| `--severity` | `low` | Minimum severity threshold (info, low, medium, high, critical) |
| `--output / -o` | -- | Write JSON report to file |

#### `investigate` command

| Option | Default | Description |
|--------|---------|-------------|
| `--severity` | `high` | Minimum severity fed to the agent |
| `--max-iterations` | `15` | Maximum agent tool-call iterations |
| `--output / -o` | -- | Write narrative to a markdown file |
| `--model` | Claude Sonnet | Override Bedrock model ID |
| `--region` | `us-east-1` | AWS region for Bedrock |

#### Global options

| Option | Description |
|--------|-------------|
| `-v / --verbose` | Enable debug logging |

## Architecture

```
pentesting_app/
  mcp_scanner/
    models.py              # RuleID, Severity, Finding, ScanResult, ParsedFile
    loader.py              # Recursive .py discovery + AST parsing
    registry.py            # @mcp.tool / @mcp.resource extraction into ServerRegistry
    engine.py              # Two-pass rule engine + severity filtering
    reporter.py            # Rich terminal table + JSON output
    cli.py                 # Click CLI with scan + investigate commands
    __main__.py            # python -m mcp_scanner entrypoint
    rules/
      base.py              # BaseRule ABC
      prompt_injection.py  # Challenge 1
      tool_poisoning.py    # Challenge 2
      excessive_permissions.py  # Challenge 3
      rug_pull.py          # Challenge 4
      tool_shadowing.py    # Challenge 5
      indirect_prompt_injection.py  # Challenge 6
      token_leakage.py     # Challenge 7
      code_execution.py    # Challenge 8
      command_injection.py # Challenge 9
      multi_vector.py      # Challenge 10 (meta-rule, post-processing)
    investigator/
      tools.py             # 4 agent tools + Bedrock toolSpec definitions
      agent.py             # Bedrock Converse loop with tool dispatch
      narrative.py         # Markdown attack narrative formatting
  tests/
    test_rules.py          # Unit tests with inline MCP snippets
    test_dvmcp.py          # Integration tests against DVMCP challenge set
```

### Static Scanner

Pure AST-based analysis using Python's `ast` module. The scanner never imports or executes target code, making it safe to run against untrusted MCP servers. The engine runs 9 standard rules in a first pass, then a multi-vector meta-rule as a post-processing step that correlates findings across rules.

### Agentic Investigator

The investigator feeds scan findings into a Claude agent via the AWS Bedrock Converse API with native tool use. The agent gets four tools:

| Tool | Purpose |
|------|---------|
| `get_function_body` | Retrieve source, params, docstring for any function |
| `check_endpoint_reachability` | Taint-trace a parameter to dangerous sinks |
| `find_related_patterns` | Search all scanned files for a string or regex |
| `get_file_imports` | List imports to identify dangerous module availability |

All tools operate on the already-parsed AST and registry -- no code execution, no network calls. The agent reasons over findings, calls tools iteratively, and produces a structured attack narrative with exploitation steps and remediation priorities.

## Validation

Tested against the [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server) challenge set (10 challenges, 10 expected findings).

```bash
pytest tests/
```

## Dependencies

- `click` -- CLI framework
- `rich` -- Terminal output formatting
- `boto3` -- AWS Bedrock access (investigate command only)
- `pytest` -- Testing
