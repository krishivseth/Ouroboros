# Ouroboros Security Platform

**Full-lifecycle security for AI agents and MCP servers**

## Demo

[![asciicast](https://asciinema.org/a/Ygpdg9uOC7ZfZsEV.svg)](https://asciinema.org/a/Ygpdg9uOC7ZfZsEV)

---

Ouroboros is a comprehensive security platform that protects AI agent workflows at every layer:

1. **Static Analysis** (`mcp_scanner`) — AST-based vulnerability detection in MCP server source code
2. **Runtime Monitoring** (`ouroboros_runtime`) — Real-time interception and validation of MCP traffic and external content
3. **Dynamic Auditing** (`ouroboros_sandbox`) — Containerized pen-testing with an LLM agent that probes live MCP servers
4. **Web Dashboard** (`Ouroboros_frontend`) — React UI for monitoring, scanning, and auditing

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Package: mcp_scanner](#package-mcp_scanner)
- [Package: ouroboros_runtime](#package-ouroboros_runtime)
- [Package: ouroboros_sandbox](#package-ouroboros_sandbox)
- [Package: ouroboros_api](#package-ouroboros_api)
- [Frontend: Ouroboros_frontend](#frontend-ouroboros_frontend)
- [API Reference](#api-reference)
- [Configuration](#configuration)
- [Development](#development)

> **For detailed technical documentation on how each backend feature works internally, see [BACKEND_DEEP_DIVE.md](./BACKEND_DEEP_DIVE.md)**

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Ouroboros Security Platform                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────────────────────┐ │
│  │ mcp_scanner  │   │ ouroboros_runtime │   │     ouroboros_sandbox       │ │
│  │              │   │                   │   │                              │ │
│  │ Static AST   │   │ Runtime Proxy     │   │ Containerized Dynamic       │ │
│  │ Analysis     │   │ + Content Probes  │   │ Pen-Testing Agent           │ │
│  │              │   │                   │   │                              │ │
│  │ 10 Detection │   │ SSL/Headers/      │   │ Docker + Claude Agent       │ │
│  │ Rules        │   │ Injection/        │   │ + Adversarial Probing       │ │
│  │              │   │ Redirect Probes   │   │                              │ │
│  └──────┬───────┘   └────────┬──────────┘   └─────────────┬────────────────┘ │
│         │                    │                            │                  │
│         └────────────────────┼────────────────────────────┘                  │
│                              │                                               │
│                    ┌─────────▼─────────┐                                     │
│                    │   ouroboros_api   │                                     │
│                    │                   │                                     │
│                    │ FastAPI Backend   │                                     │
│                    │ REST + WebSocket  │                                     │
│                    │ SSE Streaming     │                                     │
│                    └─────────┬─────────┘                                     │
│                              │                                               │
│                    ┌─────────▼─────────┐                                     │
│                    │ Ouroboros_frontend│                                     │
│                    │                   │                                     │
│                    │ React + Vite      │                                     │
│                    │ shadcn/ui         │                                     │
│                    │ Real-time UI      │                                     │
│                    └───────────────────┘                                     │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Prerequisites

- Python 3.10+
- Node.js 18+ (for frontend)
- Docker (for sandbox auditing)
- AWS credentials (for Bedrock-powered features)

### Backend Setup

```bash
# Clone the repository
git clone <repo-url>
cd pentesting_app

# Install Python dependencies
pip install -r requirements.txt

# Install additional runtime dependencies
pip install fastapi uvicorn sse-starlette aiohttp docker boto3
```

### Frontend Setup

```bash
cd Ouroboros_frontend
npm install
```

### Environment Variables

Create a `.env` file or export these variables:

```bash
# AWS Bedrock (required for investigation/sandbox features)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret

# Optional: External threat intelligence APIs
GOOGLE_SAFE_BROWSING_API_KEY=your_key  # For malware/phishing detection
VIRUSTOTAL_API_KEY=your_key            # For URL reputation checks
```

---

## Quick Start

### 1. Start the Backend API

```bash
python -m uvicorn ouroboros_api.main:app --host 0.0.0.0 --port 8000
```

### 2. Start the Frontend

```bash
cd Ouroboros_frontend
VITE_USE_REAL_API=true npm run dev
```

### 3. Open the Dashboard

Navigate to `http://localhost:5173` in your browser.

---

## Package: mcp_scanner

**Static AST-based vulnerability scanner for MCP servers**

### Features

- Pure AST analysis — never imports or executes target code
- 10 detection rules mapped to the DVMCP challenge set
- Agentic investigation layer using Claude via AWS Bedrock
- JSON and terminal output formats

### Detection Rules

| # | Rule ID | Severity | Description |
|---|---------|----------|-------------|
| 1 | `prompt-injection` | HIGH | Resources reflecting unsanitized input into LLM context |
| 2 | `tool-poisoning` | CRITICAL | Coercive LLM instructions hidden in tool docstrings |
| 3 | `excessive-permissions` | HIGH | Path traversal via unrestricted `open()`/`os.path.exists()` |
| 4 | `rug-pull` | CRITICAL | Runtime mutation of tool `__doc__` after installation |
| 5 | `tool-shadowing` | HIGH | Duplicate tool names or cross-tool resource references |
| 6 | `indirect-prompt-injection` | HIGH | User content passed through to LLM context unsanitized |
| 7 | `token-leakage` | CRITICAL | Secrets interpolated into tool return values |
| 8 | `code-execution` | CRITICAL | User input flowing to subprocess/eval/exec sinks |
| 9 | `command-injection` | CRITICAL | Shell commands built from f-string interpolation |
| 10 | `multi-vector` | CRITICAL | 3+ distinct vulnerabilities in a single server file |

### CLI Usage

```bash
# Basic scan
python -m mcp_scanner scan /path/to/mcp/server

# JSON output
python -m mcp_scanner scan /path/to/server --format json --output report.json

# Filter by severity
python -m mcp_scanner scan /path/to/server --severity high

# Agentic investigation (requires AWS Bedrock)
python -m mcp_scanner investigate /path/to/server --max-iterations 15
```

### Directory Structure

```
mcp_scanner/
├── models.py              # RuleID, Severity, Finding, ScanResult
├── loader.py              # Recursive .py discovery + AST parsing
├── registry.py            # @mcp.tool / @mcp.resource extraction
├── engine.py              # Two-pass rule engine
├── reporter.py            # Terminal + JSON output
├── cli.py                 # Click CLI
├── rules/
│   ├── base.py            # BaseRule ABC
│   ├── prompt_injection.py
│   ├── tool_poisoning.py
│   ├── excessive_permissions.py
│   ├── rug_pull.py
│   ├── tool_shadowing.py
│   ├── indirect_prompt_injection.py
│   ├── token_leakage.py
│   ├── code_execution.py
│   ├── command_injection.py
│   └── multi_vector.py    # Meta-rule (post-processing)
└── investigator/
    ├── tools.py           # 4 agent tools for Bedrock
    ├── agent.py           # Bedrock Converse loop
    └── narrative.py       # Attack narrative formatting
```

---

## Package: ouroboros_runtime

**Runtime security layer for validating external content and MCP traffic**

### Features

- **Core Probes**: Protocol-agnostic validation for any external content
  - SSL/TLS certificate validation
  - HTTP security header analysis
  - Redirect chain tracing
  - Prompt injection pattern detection
  - Content sanitization (hidden text, invisible elements)
  - Exfiltration detection with canary tokens

- **External Threat Intelligence** (optional):
  - Google Safe Browsing API integration
  - VirusTotal URL reputation checks

- **MCP Proxy**: Protocol-aware interception for MCP traffic
  - stdio transport proxy
  - Tool call interception
  - Response scanning
  - Canary token injection for cross-tool exfiltration detection

- **Policy Engine**: Configurable enforcement (block/warn/log)

### CLI Usage

```bash
# Scan a URL
python -m ouroboros_runtime scan https://example.com

# Run as MCP proxy (wraps an MCP server)
python -m ouroboros_runtime proxy --command "npx @modelcontextprotocol/server-google-maps"

# Start the API server
python -m ouroboros_runtime serve --port 8000
```

### Directory Structure

```
ouroboros_runtime/
├── core/
│   ├── engine.py          # Orchestrates probe execution
│   ├── verdict.py         # SAFE/CAUTION/BLOCK verdict system
│   ├── cache.py           # LRU verdict cache with TTL
│   └── probes/
│       ├── base.py        # BaseProbe ABC
│       ├── ssl_probe.py   # TLS certificate validation
│       ├── headers.py     # Security header analysis
│       ├── redirect.py    # Redirect chain tracing
│       ├── injection.py   # Prompt injection patterns
│       ├── content.py     # Hidden text detection
│       ├── exfiltration.py# Canary token injection
│       ├── safebrowsing.py# Google Safe Browsing API
│       └── virustotal.py  # VirusTotal API
├── mcp/
│   ├── proxy_stdio.py     # stdin/stdout MCP proxy
│   ├── interceptor.py     # Bidirectional message interception
│   ├── canary.py          # Canary token generation/tracking
│   └── probes/
│       ├── schema_drift.py    # Response schema validation
│       ├── behavioral.py      # Response consistency checks
│       └── cross_tool.py      # Cross-server exfiltration
└── policy/
    ├── loader.py          # YAML policy parser
    ├── enforcer.py        # Verdict → action mapping
    └── defaults.yaml      # Default enforcement policy
```

---

## Package: ouroboros_sandbox

**Containerized dynamic pen-testing with an LLM agent**

### Features

- **Docker Container Management**: Isolated execution environment
- **MCP Client**: Connects to servers via stdio transport
- **LLM Auditor Agent**: Claude-powered adversarial probing
- **Tool Risk Scoring**: Automatic risk assessment based on tool names/descriptions
- **Adversarial Playbook**: Path traversal, command injection, SSRF probes
- **Dynamic Iteration Budget**: Scales with number of tools

### How It Works

1. **Clone**: Fetches the target MCP server from GitHub
2. **Build**: Creates a Docker container with dependencies
3. **Start**: Launches the MCP server inside the container
4. **Probe**: LLM agent iteratively calls tools with adversarial inputs
5. **Report**: Generates unified findings with static + dynamic results

### CLI Usage

```bash
# Audit a GitHub repository
python -m ouroboros_sandbox audit https://github.com/user/mcp-server

# With custom start command
python -m ouroboros_sandbox audit https://github.com/user/mcp-server \
  --start-command "python -m server" \
  --base-image python:3.11-slim

# Increase iteration budget
python -m ouroboros_sandbox audit https://github.com/user/mcp-server \
  --max-iterations 30
```

### Directory Structure

```
ouroboros_sandbox/
├── container/
│   ├── manager.py         # Docker lifecycle management
│   ├── mcp_client.py      # MCP protocol client
│   └── network.py         # Network monitoring
├── agent/
│   ├── auditor.py         # Main audit orchestration
│   ├── tools.py           # Agent tools (list_tools, call_tool, etc.)
│   └── prompts.py         # System prompts with adversarial playbook
├── probes/
│   ├── tool_risk.py       # Tool schema risk scoring
│   ├── response_injection.py
│   ├── behavioral.py
│   └── schema_drift.py
└── report/
    └── unified.py         # Combined static + dynamic report
```

---

## Package: ouroboros_api

**FastAPI backend serving all Ouroboros features**

### Endpoints

#### Health & Status
- `GET /api/health` — Health check
- `GET /api/version` — API version

#### Static Scanning
- `POST /api/scan` — Start a static scan job
- `GET /api/scan/{job_id}` — Get scan results
- `GET /api/scan/{job_id}/stream` — SSE stream of scan progress

#### Sandbox Auditing
- `POST /api/audit` — Start a sandbox audit job
- `GET /api/audit/{job_id}` — Get audit results
- `GET /api/audit/{job_id}/stream` — SSE stream of audit progress

#### Runtime URL Scanning
- `POST /api/runtime/scan` — Scan a URL with all probes
- `GET /api/runtime/scan/{job_id}` — Get scan results
- `GET /api/runtime/scan/{job_id}/stream` — SSE stream of probe results
- `GET /api/runtime/probes` — List available probes and their status

#### Real-time Monitoring
- `WebSocket /api/monitor/ws` — Real-time MCP traffic events
- `GET /api/monitor/status` — Monitor connection status
- `POST /api/monitor/emit` — Emit events (used by proxy)

### Directory Structure

```
ouroboros_api/
├── main.py                # FastAPI app with all routes
├── models.py              # Pydantic request/response models
├── jobs.py                # In-memory job store
├── streaming.py           # SSE event emitter utilities
└── monitor.py             # WebSocket event bus for real-time monitoring
```

---

## Frontend: Ouroboros_frontend

**React dashboard for monitoring, scanning, and auditing**

### Tech Stack

- **React 18** with TypeScript
- **Vite** for fast development
- **shadcn/ui** component library
- **Tailwind CSS** for styling
- **React Query** for data fetching

### Pages & Features

#### Monitor Tab
Real-time MCP traffic monitoring with:
- Live feed of intercepted calls
- Probe results with reasoning chain
- Verdict badges (SAFE/CAUTION/BLOCK)
- Findings table with severity levels
- Raw request/response data viewer
- WebSocket connection to backend

#### Scan Tab
URL/endpoint security scanning with:
- Input for URL or MCP tool name
- Real-time probe execution via SSE
- Reasoning chain visualization
- External threat intelligence (Safe Browsing, VirusTotal)
- Scan history

#### Sandbox Tab
Dynamic MCP server auditing with:
- GitHub URL input
- Container build/start progress
- Agent reasoning stream
- Tool probing results
- Unified findings report
- Attack narrative generation

### Key Components

```
Ouroboros_frontend/src/
├── pages/
│   └── Index.tsx          # Main page with tab navigation
├── components/
│   ├── TopBar.tsx         # Navigation header
│   ├── MonitorFeed.tsx    # Real-time traffic list
│   ├── DetailPanel.tsx    # Selected item details
│   ├── ReasoningChain.tsx # Probe step visualization
│   ├── ProbeStep.tsx      # Individual probe result
│   ├── FindingsTable.tsx  # Findings with severity
│   ├── VerdictBadge.tsx   # SAFE/CAUTION/BLOCK badge
│   ├── ScanInput.tsx      # URL input for scanning
│   ├── ScanHistory.tsx    # Previous scan results
│   └── sandbox/
│       ├── SandboxInput.tsx      # Audit configuration
│       ├── AuditProgress.tsx     # Build/start progress
│       ├── AuditReport.tsx       # Final report view
│       ├── AgentReasoningStream.tsx
│       ├── ContainerLogs.tsx
│       ├── NetworkActivityLog.tsx
│       └── UnifiedFindingsTable.tsx
├── hooks/
│   ├── useMonitorWebSocket.ts    # Real WebSocket connection
│   ├── useMockWebSocket.ts       # Mock data for development
│   ├── useRuntimeScan.ts         # Real scan API
│   ├── useMockSSEScan.ts         # Mock scan data
│   ├── useSandboxAudit.ts        # Real audit API
│   └── useMockSandboxAudit.ts    # Mock audit data
└── types/
    └── ouroboros.ts       # TypeScript type definitions
```

### Environment Variables

```bash
# Use real API (default: mock data)
VITE_USE_REAL_API=true

# API URL (default: http://localhost:8000)
VITE_API_URL=http://localhost:8000
```

---

## API Reference

### Static Scan Request

```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/user/mcp-server"}'
```

### Sandbox Audit Request

```bash
curl -X POST http://localhost:8000/api/audit \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://github.com/user/mcp-server",
    "start_command": "python -m server",
    "base_image": "python:3.11-slim"
  }'
```

### Runtime URL Scan Request

```bash
curl -X POST http://localhost:8000/api/runtime/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "include_safebrowsing": true,
    "include_virustotal": false
  }'
```

### WebSocket Monitor Connection

```javascript
const ws = new WebSocket("ws://localhost:8000/api/monitor/ws");
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // data.type: "call_start" | "probe_result" | "verdict" | "escalation_*"
};
```

---

## Monitor Tab Setup

The Monitor tab provides real-time interception of MCP traffic. To use it, you need to configure your MCP client (Claude Desktop, Cursor, etc.) to route traffic through the Ouroboros proxy.

### Prerequisites

1. Start the Ouroboros API server:
   ```bash
   cd /Users/krishivseth/pentesting_app
   python -m uvicorn ouroboros_api.main:app --reload --port 8000
   ```

2. Start the frontend:
   ```bash
   cd Ouroboros_frontend
   VITE_USE_REAL_API=true npm run dev
   ```

### Claude Desktop Configuration

Edit your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "your-mcp-server": {
      "command": "python",
      "args": [
        "-m", "ouroboros_runtime.mcp.proxy_stdio",
        "--",
        "python", "-m", "your_mcp_server"
      ],
      "env": {
        "OUROBOROS_API_URL": "http://localhost:8000"
      }
    }
  }
}
```

The proxy wraps your MCP server command and intercepts all traffic.

### Cursor Configuration

For Cursor IDE, add to your MCP settings:

```json
{
  "mcpServers": {
    "proxied-server": {
      "command": "python",
      "args": [
        "-m", "ouroboros_runtime.mcp.proxy_stdio",
        "--",
        "npx", "-y", "@your-org/mcp-server"
      ]
    }
  }
}
```

### Proxy CLI Options

```bash
python -m ouroboros_runtime.mcp.proxy_stdio [OPTIONS] -- <server_command>

Options:
  --policy PATH       Custom policy.yaml file
  --api-url URL       Ouroboros API URL (default: http://localhost:8000)
  --no-emit           Disable event emission to API
```

### Verifying the Connection

1. Open the Ouroboros frontend at `http://localhost:5173`
2. Navigate to the **Monitor** tab
3. The connection indicator should show "Connected"
4. Make an MCP tool call from Claude Desktop or Cursor
5. The call should appear in the Monitor feed with:
   - Probe results (injection, SSL, headers, etc.)
   - Verdict badge (SAFE/CAUTION/BLOCK)
   - Findings if any issues detected

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Disconnected" in Monitor tab | Ensure API server is running on port 8000 |
| No traffic appearing | Verify proxy is in the MCP server command chain |
| "Proxy not running" status | The proxy emits events only when MCP calls occur |

---

## Configuration

### Policy Configuration

Create `policy.yaml` to customize enforcement actions per rule:

```yaml
# Ouroboros Runtime Policy Configuration

policies:
  # Block high-severity injection attempts
  RESPONSE_INJECTION:
    action: block
    severity_threshold: high
  
  # Block exfiltration signals
  EXFILTRATION_SIGNAL:
    action: block
    severity_threshold: medium
  
  # Warn on content issues
  MALICIOUS_CONTENT:
    action: warn
    severity_threshold: medium
  
  # Log header misconfigurations (low priority)
  HEADER_MISCONFIGURATION:
    action: log

# Per-domain overrides (allowlist trusted internal services)
allowlist:
  - domain: "*.trusted-internal.com"
    rules:
      HEADER_MISCONFIGURATION: skip
      MALICIOUS_CONTENT: log

# Global settings
settings:
  escalation: false        # LLM escalation not yet implemented
  cache_ttl_seconds: 300   # 5 minute verdict cache
  max_cache_size: 1024     # Maximum cached verdicts
```

**Available actions:** `block`, `warn`, `log`, `skip`

**Available severity thresholds:** `critical`, `high`, `medium`, `low`, `info`

### Probe Configuration

Probes can be enabled/disabled via environment variables:

```bash
# Disable external API probes
GOOGLE_SAFE_BROWSING_API_KEY=  # Empty = disabled
VIRUSTOTAL_API_KEY=            # Empty = disabled
```

---

## Development

### Running Tests

```bash
# Static scanner tests
pytest tests/test_rules.py

# DVMCP integration tests
pytest tests/test_dvmcp.py

# All tests
pytest tests/
```

### Development Mode (Mock Data)

```bash
# Frontend with mock data (no backend needed)
cd Ouroboros_frontend
npm run dev  # VITE_USE_REAL_API defaults to false
```

### Production Mode (Real API)

```bash
# Terminal 1: Backend
python -m uvicorn ouroboros_api.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Frontend
cd Ouroboros_frontend
VITE_USE_REAL_API=true npm run dev
```

---

## Threat Model

### Static Scanner Threats
- Tool poisoning via malicious docstrings
- Prompt injection through resource templates
- Code execution via eval/exec/subprocess
- Token leakage in return values
- Rug-pull attacks (runtime doc mutation)

### Runtime Threats
- Prompt injection in external content
- Context window exfiltration
- Redirect-based spoofing
- Malicious content in fetched resources
- Cross-tool data leakage

### MCP-Specific Threats
- Response payload injection
- Schema drift (declared vs actual)
- Behavioral inconsistency
- Cross-server exfiltration

---

## Competitive Positioning

| Tool | Focus | Ouroboros Advantage |
|------|-------|---------------------|
| Codex Security | Code vulnerabilities | We scan MCP-specific patterns |
| Promptfoo | AI system testing | We validate external data, not the model |
| MCP-Scan | MCP proxy | We add static analysis + sandbox auditing |
| Agent Wall | Traffic interception | We add LLM-powered investigation |

**Ouroboros provides full-lifecycle security**: static analysis before deployment, runtime validation during operation, and dynamic auditing for comprehensive pen-testing.

---

## Known Limitations

Ouroboros is under active development. The following limitations should be understood before deployment:

### Static Scanner (`mcp_scanner`)

| Limitation | Impact |
|------------|--------|
| **Python-only** | Cannot analyze MCP servers written in JavaScript, TypeScript, Go, Rust, or other languages |
| **FastMCP decorator patterns only** | Misses raw JSON-RPC class-based implementations that don't use `@mcp.tool()` decorators |
| **No cross-file taint tracking** | Data flow analysis is limited to single-file scope |

### Runtime Engine (`ouroboros_runtime`)

| Limitation | Impact |
|------------|--------|
| **Regex-based injection detection** | Misses obfuscated payloads: homoglyphs, base64-encoded instructions, multi-language attacks, jailbreak prefixes |
| **LLM escalation not implemented** | The `escalation: true` config option exists but has no code path — all detection is deterministic |
| **stdio proxy only** | No SSE or Streamable HTTP transport proxy — remote MCP servers cannot be intercepted |
| **Canary tokens may be stripped** | MCP servers that ignore `_meta` fields will not propagate canary tokens for cross-tool exfiltration detection |

### Sandbox Auditor (`ouroboros_sandbox`)

| Limitation | Impact |
|------------|--------|
| **Requires Docker** | The Docker daemon must be running locally; no remote container support |
| **Requires AWS Bedrock** | Agent features require valid AWS credentials with Bedrock access |
| **Iteration budget includes setup** | Agent may spend iterations on file exploration before adversarial probing begins |

### Performance

| Limitation | Impact |
|------------|--------|
| **No profiling data** | Stated latency targets (10ms cached, 200ms deterministic, 3s with LLM) have not been validated |

---

## License

MIT

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `pytest tests/`
5. Submit a pull request

---

## Acknowledgments

- Tested against [Damn Vulnerable MCP Server](https://github.com/harishsg993010/damn-vulnerable-MCP-server)
- Built with [Claude](https://anthropic.com) via AWS Bedrock
- UI components from [shadcn/ui](https://ui.shadcn.com)
