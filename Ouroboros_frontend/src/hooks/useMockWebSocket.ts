import { useEffect, useRef, useCallback, useState } from "react";
import type {
  RuntimeVerdict,
  Finding,
  ProbeStepData,
  Verdict,
  EnforcementAction,
  WsEvent,
  TargetMode,
} from "@/types/ouroboros";

const TARGETS = [
  { target: "https://api.openweathermap.org/data/2.5/weather?q=London", type: "url" as TargetMode },
  { target: "weather_lookup", type: "mcp" as TargetMode, toolName: "weather_lookup" },
  { target: "https://maps.googleapis.com/maps/api/geocode/json", type: "url" as TargetMode },
  { target: "web_search", type: "mcp" as TargetMode, toolName: "web_search" },
  { target: "https://api.github.com/repos/user/repo/contents", type: "url" as TargetMode },
  { target: "file_read", type: "mcp" as TargetMode, toolName: "file_read" },
  { target: "https://jsonplaceholder.typicode.com/posts", type: "url" as TargetMode },
  { target: "database_query", type: "mcp" as TargetMode, toolName: "database_query" },
  { target: "https://api.stripe.com/v1/charges", type: "url" as TargetMode },
  { target: "send_email", type: "mcp" as TargetMode, toolName: "send_email" },
  { target: "https://hooks.slack.com/services/T00/B00/XXX", type: "url" as TargetMode },
  { target: "code_execute", type: "mcp" as TargetMode, toolName: "code_execute" },
];

const ESCALATION_TEXTS = [
  'The base64 string decodes to weather coordinate data, not an instruction payload. The content appears to be standard geographic encoding used by the weather API. Benign.',
  'The response contains a markdown image tag pointing to an external domain. However, analysis shows this is the API\'s standard logo asset served from their CDN, not an exfiltration attempt via pixel tracking.',
  'Detected unusual JSON nesting depth (12 levels). Upon analysis, this is a legitimate GraphQL response structure. No embedded instructions or prompt injection patterns found in any nested field.',
  'The response includes a base64-encoded SVG that contains JavaScript. While the script only handles animation, this is a potential XSS vector if rendered in a browser context. Flagging as CAUTION.',
  'Multiple redirect chains detected (3 hops). Final destination resolves to the same organization\'s CDN. Certificate chain is valid throughout. No domain spoofing detected.',
  'Response body contains text that resembles a system prompt override attempt: "Ignore previous instructions and..." This appears to be a prompt injection attack embedded in the API response.',
];

const PROBE_TEMPLATES = {
  classify: (t: { type: TargetMode; toolName?: string; target: string }): ProbeStepData => ({
    id: crypto.randomUUID(),
    name: "CLASSIFY",
    duration_ms: 8 + Math.random() * 12,
    status: "complete",
    detail: [
      `Target type: ${t.type === "mcp" ? "MCP tool call" : "HTTP endpoint"}`,
      t.type === "mcp" ? `Tool: ${t.toolName}` : `URL: ${t.target}`,
      t.type === "mcp"
        ? `Server: ${t.toolName}.mcp-server.local`
        : `Host: ${new URL(t.target).hostname}`,
    ],
    findings: [],
  }),
  injection: (hasFinding: boolean): ProbeStepData => {
    const findings: Finding[] = hasFinding
      ? [
          {
            id: crypto.randomUUID(),
            severity: Math.random() > 0.5 ? "HIGH" : "CRITICAL",
            rule: "PROMPT_INJECTION",
            evidence: 'Detected coercive pattern: "Ignore previous instructions"',
            detail: 'Response body line 47 contains instruction override attempt.',
          },
        ]
      : [];
    return {
      id: crypto.randomUUID(),
      name: "PROBE: injection",
      duration_ms: 5 + Math.random() * 15,
      status: "complete",
      detail: [
        `Scanned response body (${(Math.random() * 10 + 0.5).toFixed(1)}KB)`,
        hasFinding ? "✗ Coercive pattern detected" : "✓ No coercive patterns",
        hasFinding
          ? "✗ Potential prompt injection"
          : "✓ No markdown image exfiltration",
        Math.random() > 0.6
          ? `⚠ Base64 content detected (${Math.floor(Math.random() * 500 + 50)} chars)`
          : "✓ No encoded payloads",
      ],
      findings,
    };
  },
  headers: (hasFinding: boolean): ProbeStepData => {
    const findings: Finding[] = hasFinding
      ? [
          {
            id: crypto.randomUUID(),
            severity: "LOW",
            rule: "HEADER_MISCONFIGURATION",
            evidence: "Missing Strict-Transport-Security header",
          },
        ]
      : [];
    return {
      id: crypto.randomUUID(),
      name: "PROBE: headers",
      duration_ms: 2 + Math.random() * 5,
      status: "complete",
      detail: [
        hasFinding ? "✗ Missing HSTS header" : "✓ HSTS present",
        Math.random() > 0.3 ? "✓ CSP present" : "⚠ Weak CSP policy",
        "✓ No server version leak",
        Math.random() > 0.5
          ? "✓ X-Content-Type-Options: nosniff"
          : "⚠ Missing X-Content-Type-Options",
      ],
      findings,
    };
  },
  ssl: (hasFinding: boolean): ProbeStepData => {
    const findings: Finding[] = hasFinding
      ? [
          {
            id: crypto.randomUUID(),
            severity: "MEDIUM",
            rule: "SSL_WEAKNESS",
            evidence: "Certificate expires in 12 days",
          },
        ]
      : [];
    const year = 2026 + Math.floor(Math.random() * 3);
    const month = String(Math.floor(Math.random() * 12) + 1).padStart(2, "0");
    return {
      id: crypto.randomUUID(),
      name: "PROBE: ssl",
      duration_ms: 10 + Math.random() * 20,
      status: "complete",
      detail: [
        hasFinding ? "⚠ Certificate expiring soon" : "✓ Valid certificate chain",
        `✓ Expires ${year}-${month}-${String(Math.floor(Math.random() * 28) + 1).padStart(2, "0")}`,
        "✓ Hostname matches",
        Math.random() > 0.8 ? "⚠ TLS 1.2 (upgrade to 1.3 recommended)" : "✓ TLS 1.3",
      ],
      findings,
    };
  },
};

function pickVerdict(): { verdict: Verdict; action: EnforcementAction } {
  const r = Math.random();
  if (r < 0.7) return { verdict: "SAFE", action: "passed" };
  if (r < 0.9) return { verdict: "CAUTION", action: "warned" };
  return { verdict: "BLOCK", action: "blocked" };
}

function generateMockCall(): {
  events: WsEvent[];
  timings: number[];
  finalVerdict: RuntimeVerdict;
} {
  const t = TARGETS[Math.floor(Math.random() * TARGETS.length)];
  const id = crypto.randomUUID();
  const timestamp = new Date().toISOString();
  const { verdict, action } = pickVerdict();

  const hasInjectionFinding = verdict === "BLOCK";
  const hasHeaderFinding = verdict !== "SAFE" || Math.random() > 0.6;
  const hasSslFinding = Math.random() > 0.85;
  const needsEscalation = verdict !== "SAFE" && Math.random() > 0.3;

  const classifyStep = PROBE_TEMPLATES.classify(t);
  const injectionStep = PROBE_TEMPLATES.injection(hasInjectionFinding);
  const headersStep = PROBE_TEMPLATES.headers(hasHeaderFinding);
  const sslStep = PROBE_TEMPLATES.ssl(hasSslFinding);

  const steps: ProbeStepData[] = [classifyStep, injectionStep, headersStep, sslStep];
  const allFindings = steps.flatMap((s) => s.findings);

  const events: WsEvent[] = [];
  const timings: number[] = [];

  // call_start
  events.push({
    type: "call_start",
    id,
    target: t.target,
    targetType: t.type,
    toolName: t.toolName,
    timestamp,
  });
  timings.push(0);

  // probe results with realistic delays
  const probeTimes = [classifyStep.duration_ms, injectionStep.duration_ms, headersStep.duration_ms, sslStep.duration_ms];
  let cumulative = 50; // initial delay
  for (let i = 0; i < steps.length; i++) {
    cumulative += probeTimes[i] + 30 + Math.random() * 80;
    events.push({
      type: "probe_result",
      id,
      probe: steps[i].name,
      duration_ms: steps[i].duration_ms,
      findings: steps[i].findings,
      detail: steps[i].detail,
    });
    timings.push(cumulative);
  }

  let escalationStep: ProbeStepData | undefined;
  if (needsEscalation) {
    const escText = ESCALATION_TEXTS[Math.floor(Math.random() * ESCALATION_TEXTS.length)];
    const escDuration = 1200 + Math.random() * 1200;

    escalationStep = {
      id: crypto.randomUUID(),
      name: "ESCALATE",
      duration_ms: escDuration,
      status: "complete",
      detail: [
        "LLM analysis triggered by flagged content",
      ],
      findings: [],
      isEscalation: true,
      escalationText: escText,
    };
    steps.push(escalationStep);

    cumulative += 100;
    events.push({ type: "escalation_start", id });
    timings.push(cumulative);

    // Stream chars in chunks
    const chunkSize = 3;
    for (let i = 0; i < escText.length; i += chunkSize) {
      cumulative += 15 + Math.random() * 30;
      events.push({
        type: "escalation_chunk",
        id,
        text: escText.slice(i, i + chunkSize),
      });
      timings.push(cumulative);
    }

    cumulative += 50;
    events.push({ type: "escalation_end", id, duration_ms: escDuration });
    timings.push(cumulative);
  }

  const totalDuration = steps.reduce((a, s) => a + s.duration_ms, 0);
  const policyRule = verdict === "BLOCK" ? "block_on_injection" : verdict === "CAUTION" ? "warn_on_misconfiguration" : undefined;

  const finalVerdict: RuntimeVerdict = {
    id,
    target: t.target,
    targetType: t.type,
    toolName: t.toolName,
    timestamp,
    verdict,
    action,
    policyRule,
    totalDuration_ms: totalDuration,
    steps,
    findings: allFindings,
    requestJson: JSON.stringify(
      {
        jsonrpc: "2.0",
        method: t.type === "mcp" ? `tools/${t.toolName}` : "GET",
        params: t.type === "mcp" ? { query: "sample input" } : {},
        id: 1,
      },
      null,
      2
    ),
    responseJson: JSON.stringify(
      {
        status: 200,
        body: { data: "sample response payload", items: [1, 2, 3] },
        headers: { "content-type": "application/json" },
      },
      null,
      2
    ),
    policyApplied: `rules:\n  - id: ${policyRule || "default_pass"}\n    action: ${action}\n    conditions:\n      - severity: >= ${verdict === "BLOCK" ? "HIGH" : "LOW"}`,
  };

  cumulative += 80;
  events.push({ type: "verdict", id, verdict: finalVerdict });
  timings.push(cumulative);

  return { events, timings, finalVerdict };
}

interface UseMockWebSocketReturn {
  connected: boolean;
  setConnected: (v: boolean) => void;
}

export function useMockWebSocket(
  onEvent: (event: WsEvent) => void,
  enabled: boolean = true
): UseMockWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const clearAllTimeouts = useCallback(() => {
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];
  }, []);

  const emitCall = useCallback(() => {
    const { events, timings } = generateMockCall();
    events.forEach((evt, i) => {
      const t = setTimeout(() => onEvent(evt), timings[i]);
      timeoutsRef.current.push(t);
    });
  }, [onEvent]);

  useEffect(() => {
    if (!enabled) return;

    // Simulate connection delay
    const connectTimeout = setTimeout(() => {
      setConnected(true);

      // Emit initial batch
      for (let i = 0; i < 5; i++) {
        setTimeout(() => emitCall(), i * 400);
      }

      // Then emit new calls periodically
      intervalRef.current = setInterval(() => {
        emitCall();
      }, 2000 + Math.random() * 4000);
    }, 800);

    return () => {
      clearTimeout(connectTimeout);
      clearAllTimeouts();
      if (intervalRef.current) clearInterval(intervalRef.current);
      setConnected(false);
    };
  }, [enabled, emitCall, clearAllTimeouts]);

  return { connected, setConnected };
}

// Export for scan mode reuse
export { generateMockCall };
