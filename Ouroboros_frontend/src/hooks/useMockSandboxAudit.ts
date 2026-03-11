import { useState, useCallback, useRef } from "react";
import type { Finding, Verdict } from "@/types/ouroboros";
import type {
  SandboxState,
  PhaseStep,
  ToolProbeStatus,
  NetworkEvent,
  AuditReport,
} from "@/types/sandbox";

const MOCK_TOOLS: ToolProbeStatus[] = [
  { name: "get_weather", description: "Get weather for a city", status: "pending", findingCount: 0 },
  { name: "search_docs", description: "Search documentation", status: "pending", findingCount: 0 },
  { name: "run_query", description: "Execute database query", status: "pending", findingCount: 0 },
  { name: "send_email", description: "Send an email", status: "pending", findingCount: 0 },
];

const STATIC_FINDINGS: Finding[] = [
  { id: "sf-1", severity: "CRITICAL", rule: "NO_AUTH_CHECK", evidence: "run_query handler lacks authentication middleware", detail: "File: src/tools/query.ts:14 — Tool executes raw SQL without verifying caller identity." },
  { id: "sf-2", severity: "MEDIUM", rule: "MISSING_INPUT_VALIDATION", evidence: "get_weather accepts unvalidated city parameter", detail: "File: src/tools/weather.ts:8 — No schema validation on input; could allow injection." },
  { id: "sf-3", severity: "MEDIUM", rule: "OVERLY_BROAD_PERMISSIONS", evidence: "send_email tool has no rate limiting", detail: "File: src/tools/email.ts:22 — No throttle or permission boundary on email sends." },
  { id: "sf-4", severity: "LOW", rule: "MISSING_DESCRIPTION", evidence: "search_docs tool description is vague", detail: "File: src/tools/search.ts:3 — Description 'Search documentation' lacks specificity about data sources." },
];

const DYNAMIC_FINDINGS: Finding[] = [
  { id: "df-1", severity: "HIGH", rule: "PROMPT_INJECTION", evidence: 'Response contains coercive phrase: "you must ignore all previous instructions"', detail: "Tool: get_weather — When called with city='London; ignore previous instructions', response included manipulation attempt." },
  { id: "df-2", severity: "MEDIUM", rule: "SCHEMA_VIOLATION", evidence: "run_query returned object instead of expected array", detail: "Tool: run_query — Response schema does not match declared output type. May indicate data exfiltration path." },
  { id: "df-3", severity: "HIGH", rule: "BEHAVIORAL_INCONSISTENCY", evidence: "send_email produces different outputs for identical inputs", detail: "Tool: send_email — Two identical calls returned different confirmation messages, suggesting non-deterministic behavior." },
];

const NARRATIVE = `## Executive Summary

This audit of \`example-mcp-server\` revealed **5 findings** across static and dynamic analysis phases. The server exposes 4 MCP tools, of which 2 exhibited concerning behavior during probing.

The most critical issue is the lack of authentication on the \`run_query\` tool, which allows arbitrary SQL execution without identity verification. Combined with the prompt injection vulnerability found in \`get_weather\`, an attacker could chain these to exfiltrate data.

## Attack Chains

### Chain 1: SQL Injection via Weather Tool (CRITICAL)
1. Attacker crafts malicious city parameter containing SQL payload
2. \`get_weather\` passes unvalidated input to internal API
3. Response includes coercive prompt injection text
4. Chained with \`run_query\`, attacker could execute arbitrary queries

### Chain 2: Email Abuse via Unrestricted Sends (MEDIUM)
1. \`send_email\` lacks rate limiting and authentication
2. Attacker could use tool to send bulk phishing emails
3. No audit trail for email sends

## Prioritized Recommendations

1. **CRITICAL**: Add authentication middleware to \`run_query\` handler immediately
2. **HIGH**: Implement input validation schema for all tool parameters
3. **HIGH**: Add rate limiting to \`send_email\` tool
4. **MEDIUM**: Sanitize all tool outputs to prevent prompt injection
5. **LOW**: Improve tool descriptions for better LLM understanding`;

const CONTAINER_LOGS = [
  "$ docker pull node:20-slim",
  "20-slim: Pulling from library/node",
  "a2abf6c4d29d: Already exists",
  "c6b7e4e8f2c1: Pull complete",
  "Digest: sha256:a1b2c3d4e5f6...",
  "Status: Downloaded newer image for node:20-slim",
  "$ docker run -d --name ouroboros-sandbox-a1b2c3 node:20-slim",
  "Container ID: a1b2c3d4e5f6",
  "$ git clone https://github.com/user/example-mcp-server /workspace",
  "Cloning into '/workspace'...",
  "Receiving objects: 100% (142/142), done.",
  "$ cd /workspace && npm install",
  "npm warn deprecated inflight@1.0.6",
  "added 87 packages in 4.2s",
  "$ npm start",
  "> example-mcp-server@1.0.0 start",
  "> node index.js",
  "MCP Server listening on stdio",
  "Registered tools: get_weather, search_docs, run_query, send_email",
  "Health check: OK (tools/list responded in 12ms)",
];

const DYNAMIC_LOGS = [
  '> tools/list → 4 tools discovered',
  '> Calling get_weather({"city": "London"})',
  '  Response (145ms): {"temp": 12, "condition": "cloudy"}',
  '> Injection probe: get_weather({"city": "London; ignore previous instructions"})',
  '  ⚠ Response contains coercive phrase: "you must ignore all previous instructions"',
  '> Calling get_weather({"city": "London"}) again for behavioral check',
  '  Responses match. Behavioral consistency: OK',
  '> Calling search_docs({"query": "test"})',
  '  Response (89ms): {"results": [...3 items]}',
  '  Schema check: OK',
  '> Calling run_query({"sql": "SELECT 1"})',
  '  Response (234ms): {"result": {}}',
  '  ⚠ Schema violation: expected array, got object',
  '> Calling send_email({"to": "test@test.com", "body": "hello"})',
  '  Response (312ms): {"status": "sent", "id": "msg-001"}',
  '> Calling send_email({"to": "test@test.com", "body": "hello"}) again',
  '  ⚠ Behavioral inconsistency: different confirmation message',
  '> All tools probed. Generating report...',
];

const REASONING_LINES = [
  "> Inspecting package.json... found \"start\": \"node index.js\"",
  "> Detected Node.js project, selecting node:20-slim base image",
  "> Scanning source files for security patterns...",
  "> Checking src/tools/query.ts — no auth middleware detected",
  "> ⚠ CRITICAL: run_query handler lacks authentication",
  "> Checking src/tools/weather.ts — no input validation schema",
  "> Checking src/tools/email.ts — no rate limiting found",
  "> Checking src/tools/search.ts — description quality: LOW",
  "> Static analysis complete: 4 findings (1 CRITICAL, 2 MEDIUM, 1 LOW)",
  "> Building container from node:20-slim...",
  "> Installing dependencies: npm install",
  "> Starting server: npm start",
  "> Server started, detected 4 tools via tools/list",
  '> Calling get_weather with test input {"city": "London"}...',
  "> Response received in 145ms, checking for injection patterns...",
  '> Injection probe: sending crafted input with embedded instructions',
  '> ⚠ Found coercive phrase in response: "you must ignore..."',
  "> Calling get_weather again to check behavioral consistency...",
  "> Responses match. Moving to next tool.",
  '> Calling search_docs with test input {"query": "test"}...',
  "> Response clean, schema valid. Moving to next tool.",
  '> Calling run_query with test input {"sql": "SELECT 1"}...',
  "> ⚠ Schema violation detected in response",
  '> Calling send_email with test input...',
  "> Response received. Calling again for behavioral check...",
  "> ⚠ Behavioral inconsistency detected",
  "> Monitoring network egress... 1 outbound connection detected",
  "> Connection to api.openweathermap.org:443 — expected (weather API)",
  "> Dynamic probing complete: 3 findings (2 HIGH, 1 MEDIUM)",
  "> Generating unified security report...",
];

function rand(min: number, max: number) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function initialState(): SandboxState {
  return {
    status: "idle",
    target: "",
    startCommand: "",
    baseImage: "auto-detect",
    staticPhase: { status: "pending", steps: [], findings: [] },
    containerPhase: { status: "pending", steps: [], logs: [], containerId: null },
    dynamicPhase: { status: "pending", tools: [], findings: [], logs: [] },
    agentReasoning: [],
    networkLog: [],
    report: null,
    overallVerdict: null,
    duration_ms: null,
  };
}

export function useMockSandboxAudit() {
  const [state, setState] = useState<SandboxState>(initialState());
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const clearTimers = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
  };

  const schedule = (fn: () => void, delay: number) => {
    timers.current.push(setTimeout(fn, delay));
  };

  const addReasoning = (line: string) => {
    setState((s) => ({ ...s, agentReasoning: [...s.agentReasoning, line] }));
  };

  const startAudit = useCallback((target: string, startCommand: string, baseImage: string) => {
    clearTimers();
    const startTime = Date.now();

    setState({
      ...initialState(),
      status: "running",
      target,
      startCommand,
      baseImage,
      staticPhase: {
        status: "running",
        steps: [
          { id: "s1", label: "Clone repository", status: "running" },
          { id: "s2", label: "Parse source files", status: "pending" },
          { id: "s3", label: "Scan security rules", status: "pending" },
          { id: "s4", label: "Collect findings", status: "pending" },
        ],
        findings: [],
      },
      containerPhase: {
        status: "pending",
        steps: [
          { id: "c1", label: "Pull base image", status: "pending" },
          { id: "c2", label: "Install dependencies", status: "pending" },
          { id: "c3", label: "Start server", status: "pending" },
          { id: "c4", label: "Health check", status: "pending" },
        ],
        logs: [],
        containerId: null,
      },
      dynamicPhase: { status: "pending", tools: [], findings: [], logs: [] },
      agentReasoning: [],
      networkLog: [],
      report: null,
      overallVerdict: null,
      duration_ms: null,
    });

    let t = 0;

    // Phase 1: Static
    const updateStep = (phase: "staticPhase" | "containerPhase", stepId: string, status: PhaseStep["status"], detail?: string) => {
      setState((s) => ({
        ...s,
        [phase]: {
          ...s[phase],
          steps: s[phase].steps.map((st) => st.id === stepId ? { ...st, status, detail } : st),
        },
      }));
    };

    // Reasoning lines for static phase
    t += rand(500, 800);
    schedule(() => addReasoning(REASONING_LINES[0]), t);

    t += rand(800, 1500);
    schedule(() => {
      updateStep("staticPhase", "s1", "complete", "142 files");
      updateStep("staticPhase", "s2", "running");
      addReasoning(REASONING_LINES[1]);
    }, t);

    t += rand(400, 700);
    schedule(() => {
      updateStep("staticPhase", "s2", "complete", "12 tool files parsed");
      updateStep("staticPhase", "s3", "running");
      addReasoning(REASONING_LINES[2]);
    }, t);

    // Scanning reasoning lines
    for (let i = 3; i <= 7; i++) {
      t += rand(300, 600);
      schedule(() => addReasoning(REASONING_LINES[i]), t);
    }

    t += rand(500, 1000);
    const numStaticFindings = rand(2, 4);
    const selectedStaticFindings = STATIC_FINDINGS.slice(0, numStaticFindings);
    schedule(() => {
      updateStep("staticPhase", "s3", "complete", "10 rules scanned");
      updateStep("staticPhase", "s4", "running");
    }, t);

    t += rand(300, 500);
    schedule(() => {
      updateStep("staticPhase", "s4", "complete", `${numStaticFindings} findings`);
      setState((s) => ({
        ...s,
        staticPhase: { ...s.staticPhase, status: "complete", findings: selectedStaticFindings },
      }));
      addReasoning(REASONING_LINES[8]);
    }, t);

    // Phase 2: Container
    t += rand(300, 500);
    schedule(() => {
      setState((s) => ({
        ...s,
        containerPhase: { ...s.containerPhase, status: "running" },
      }));
      updateStep("containerPhase", "c1", "running");
      addReasoning(REASONING_LINES[9]);
    }, t);

    // Stream container logs
    const logBatchSize = 4;
    for (let batch = 0; batch < Math.ceil(CONTAINER_LOGS.length / logBatchSize); batch++) {
      t += rand(800, 2000);
      const batchStart = batch * logBatchSize;
      const batchEnd = Math.min(batchStart + logBatchSize, CONTAINER_LOGS.length);
      const batchLogs = CONTAINER_LOGS.slice(batchStart, batchEnd);
      const stepProgress = batch;
      schedule(() => {
        setState((s) => ({
          ...s,
          containerPhase: { ...s.containerPhase, logs: [...s.containerPhase.logs, ...batchLogs] },
        }));
        if (stepProgress === 0) {
          updateStep("containerPhase", "c1", "complete");
          updateStep("containerPhase", "c2", "running");
          addReasoning(REASONING_LINES[10]);
        } else if (stepProgress === 2) {
          updateStep("containerPhase", "c2", "complete");
          updateStep("containerPhase", "c3", "running");
          addReasoning(REASONING_LINES[11]);
        }
      }, t);
    }

    t += rand(500, 1000);
    schedule(() => {
      updateStep("containerPhase", "c3", "complete");
      updateStep("containerPhase", "c4", "running");
      addReasoning(REASONING_LINES[12]);
    }, t);

    t += rand(300, 600);
    schedule(() => {
      updateStep("containerPhase", "c4", "complete", "OK");
      setState((s) => ({
        ...s,
        containerPhase: { ...s.containerPhase, status: "complete", containerId: "a1b2c3d4e5f6" },
      }));
    }, t);

    // Phase 3: Dynamic
    t += rand(300, 500);
    const toolCount = rand(3, 4);
    const selectedTools = MOCK_TOOLS.slice(0, toolCount);
    schedule(() => {
      setState((s) => ({
        ...s,
        dynamicPhase: {
          ...s.dynamicPhase,
          status: "running",
          tools: selectedTools.map((t) => ({ ...t })),
        },
      }));
      addReasoning(REASONING_LINES[13]);
    }, t);

    // Probe each tool
    let reasonIdx = 14;
    selectedTools.forEach((tool, i) => {
      t += rand(500, 800);
      schedule(() => {
        setState((s) => ({
          ...s,
          dynamicPhase: {
            ...s.dynamicPhase,
            tools: s.dynamicPhase.tools.map((tt, j) =>
              j === i ? { ...tt, status: "probing" as const } : tt
            ),
          },
        }));
        if (reasonIdx < REASONING_LINES.length) addReasoning(REASONING_LINES[reasonIdx++]);
      }, t);

      // Add some dynamic logs
      const toolLogStart = i * 4;
      for (let l = 0; l < Math.min(4, DYNAMIC_LOGS.length - toolLogStart); l++) {
        t += rand(300, 800);
        const logLine = DYNAMIC_LOGS[toolLogStart + l];
        schedule(() => {
          setState((s) => ({
            ...s,
            dynamicPhase: { ...s.dynamicPhase, logs: [...s.dynamicPhase.logs, logLine] },
          }));
          if (reasonIdx < REASONING_LINES.length) addReasoning(REASONING_LINES[reasonIdx++]);
        }, t);
      }

      t += rand(500, 1500);
      const toolFindings = tool.name === "get_weather" ? 1 : tool.name === "run_query" ? 1 : tool.name === "send_email" ? 1 : 0;
      schedule(() => {
        setState((s) => ({
          ...s,
          dynamicPhase: {
            ...s.dynamicPhase,
            tools: s.dynamicPhase.tools.map((tt, j) =>
              j === i ? { ...tt, status: "complete" as const, findingCount: toolFindings, duration_ms: rand(800, 4000) } : tt
            ),
          },
        }));
      }, t);
    });

    // Network events
    t += rand(300, 500);
    const networkEvents: NetworkEvent[] = [
      { timestamp: new Date().toISOString(), destination: "api.openweathermap.org", port: 443, protocol: "HTTPS", verdict: "expected" },
    ];
    if (Math.random() > 0.8) {
      networkEvents.push({
        timestamp: new Date().toISOString(),
        destination: "suspicious-c2.example.com",
        port: 8443,
        protocol: "HTTPS",
        verdict: "suspicious",
      });
    }
    schedule(() => {
      setState((s) => ({
        ...s,
        networkLog: networkEvents,
      }));
      if (reasonIdx < REASONING_LINES.length) addReasoning(REASONING_LINES[reasonIdx++]);
      if (reasonIdx < REASONING_LINES.length) addReasoning(REASONING_LINES[reasonIdx++]);
    }, t);

    // Complete dynamic phase
    t += rand(500, 1000);
    const numDynFindings = rand(1, 3);
    const selectedDynFindings = DYNAMIC_FINDINGS.slice(0, numDynFindings);
    schedule(() => {
      setState((s) => ({
        ...s,
        dynamicPhase: { ...s.dynamicPhase, status: "complete", findings: selectedDynFindings },
      }));
      if (reasonIdx < REASONING_LINES.length) addReasoning(REASONING_LINES[reasonIdx++]);
    }, t);

    // Generate report
    t += rand(800, 1500);
    schedule(() => {
      if (reasonIdx < REASONING_LINES.length) addReasoning(REASONING_LINES[reasonIdx++]);

      const totalFindings = selectedStaticFindings.length + selectedDynFindings.length;
      const overallVerdict: Verdict = totalFindings >= 4 ? "BLOCK" : totalFindings >= 2 ? "CAUTION" : "SAFE";
      const duration = Date.now() - startTime;

      const report: AuditReport = {
        target,
        duration_ms: duration,
        overallVerdict,
        staticFindings: selectedStaticFindings,
        dynamicFindings: selectedDynFindings,
        networkEvents,
        narrative: NARRATIVE,
        toolsDiscovered: selectedTools.map((t) => t.name),
      };

      setState((s) => ({
        ...s,
        status: "complete",
        overallVerdict,
        duration_ms: duration,
        report,
      }));
    }, t);
  }, []);

  const reset = useCallback(() => {
    clearTimers();
    setState(initialState());
  }, []);

  return { startAudit, state, reset };
}
