import { useState, useCallback, useRef } from "react";
import type { Finding, Verdict } from "@/types/ouroboros";
import type {
  SandboxState,
  PhaseStep,
  ToolProbeStatus,
  NetworkEvent,
  AuditReport,
} from "@/types/sandbox";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

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

interface AuditRequest {
  target_path: string;
  start_command?: string;
  base_image?: string;
  max_iterations?: number;
  skip_static?: boolean;
}

export function useSandboxAudit() {
  const [state, setState] = useState<SandboxState>(initialState());
  const eventSourceRef = useRef<EventSource | null>(null);
  const jobIdRef = useRef<string | null>(null);

  const closeEventSource = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  };

  // Define fetchFinalResult FIRST since it's used by other callbacks
  const fetchFinalResult = useCallback(async (jobId: string) => {
    try {
      const response = await fetch(`${API_BASE}/api/sandbox/audit/${jobId}`);
      if (!response.ok) throw new Error("Failed to fetch result");
      
      const result = await response.json();
      console.log("Fetched result:", result);
      
      if (result.status === "completed") {
        const verdict = (result.verdict || "safe").toUpperCase() as Verdict;
        
        const report: AuditReport = {
          target: result.target_path,
          duration_ms: (result.duration_seconds || 0) * 1000,
          overallVerdict: verdict,
          staticFindings: (result.static_findings || []).map((f: any) => ({
            id: `sf-${Math.random().toString(36).slice(2, 8)}`,
            severity: (f.severity || "low").toUpperCase(),
            rule: f.rule_id || "unknown",
            evidence: f.title || "",
            detail: f.description || "",
          })),
          dynamicFindings: (result.dynamic_findings || []).map((f: any) => ({
            id: `df-${Math.random().toString(36).slice(2, 8)}`,
            severity: (f.severity || "low").toUpperCase(),
            rule: f.rule_id || "unknown",
            evidence: f.title || "",
            detail: f.description || "",
          })),
          networkEvents: (result.network_events || []).map((e: any) => ({
            timestamp: e.timestamp,
            destination: e.destination,
            port: e.port,
            protocol: e.protocol,
            verdict: "expected" as const,
          })),
          narrative: result.narrative || "",
          toolsDiscovered: (result.tools_probed || []).map((t: any) => t.tool_name),
        };

        setState((s) => ({
          ...s,
          status: "complete",
          overallVerdict: verdict,
          duration_ms: (result.duration_seconds || 0) * 1000,
          report,
        }));
      } else {
        console.log("Result not completed yet:", result.status);
      }
    } catch (error) {
      console.error("Failed to fetch final result:", error);
      setState((s) => ({
        ...s,
        status: "error",
        agentReasoning: [...s.agentReasoning, `> ERROR: Failed to fetch result`],
      }));
    }
  }, []);

  const startAudit = useCallback(async (target: string, startCommand: string, baseImage: string) => {
    closeEventSource();
    
    setState({
      ...initialState(),
      status: "running",
      target,
      startCommand,
      baseImage,
    });

    try {
      const request: AuditRequest = {
        target_path: target,
        start_command: startCommand || undefined,
        base_image: baseImage === "auto-detect" ? "python:3.12-slim" : baseImage,
      };

      const response = await fetch(`${API_BASE}/api/sandbox/audit`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(request),
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || "Failed to start audit");
      }

      const { job_id } = await response.json();
      jobIdRef.current = job_id;

      const eventSource = new EventSource(`${API_BASE}/api/sandbox/audit/${job_id}/stream`);
      eventSourceRef.current = eventSource;

      eventSource.onopen = () => {
        setState((s) => ({ ...s, agentReasoning: [...s.agentReasoning, "> Connected to audit stream"] }));
      };

      const handleEvent = (eventType: string, data: Record<string, unknown>) => {
        switch (eventType) {
          case "phase": {
            const phase = data.phase as string;
            const status = data.status as string;
            
            if (phase === "initializing") {
              setState((s) => ({ ...s, agentReasoning: [...s.agentReasoning, "> Initializing audit..."] }));
            } else if (phase === "static_scan") {
              if (status === "running") {
                setState((s) => ({
                  ...s,
                  staticPhase: {
                    ...s.staticPhase,
                    status: "running",
                    steps: [
                      { id: "s1", label: "Scanning source files", status: "running" },
                      { id: "s2", label: "Analyzing AST patterns", status: "pending" },
                      { id: "s3", label: "Collecting findings", status: "pending" },
                    ],
                  },
                  agentReasoning: [...s.agentReasoning, "> Running static analysis..."],
                }));
              } else if (status === "completed") {
                setState((s) => ({
                  ...s,
                  staticPhase: {
                    ...s.staticPhase,
                    status: "complete",
                    steps: s.staticPhase.steps.map((st) => ({ ...st, status: "complete" as const })),
                  },
                  agentReasoning: [...s.agentReasoning, "> Static analysis complete"],
                }));
              }
            } else if (phase === "container_setup") {
              if (status === "running") {
                setState((s) => ({
                  ...s,
                  containerPhase: {
                    ...s.containerPhase,
                    status: "running",
                    steps: [
                      { id: "c1", label: "Creating container", status: "running" },
                      { id: "c2", label: "Mounting workspace", status: "pending" },
                      { id: "c3", label: "Starting server", status: "pending" },
                    ],
                    logs: [...s.containerPhase.logs, "$ docker create --name ouroboros-sandbox ..."],
                  },
                  agentReasoning: [...s.agentReasoning, "> Setting up Docker container..."],
                }));
              } else if (status === "completed") {
                setState((s) => ({
                  ...s,
                  containerPhase: {
                    ...s.containerPhase,
                    status: "complete",
                    steps: s.containerPhase.steps.map((st) => ({ ...st, status: "complete" as const })),
                    containerId: "sandbox-container",
                    logs: [...s.containerPhase.logs, "Container started successfully"],
                  },
                  agentReasoning: [...s.agentReasoning, "> Container ready"],
                }));
              }
            } else if (phase === "agent_probing") {
              if (status === "running") {
                setState((s) => ({
                  ...s,
                  dynamicPhase: { ...s.dynamicPhase, status: "running" },
                  agentReasoning: [...s.agentReasoning, "> Starting adversarial probing..."],
                }));
              } else if (status === "completed") {
                setState((s) => ({
                  ...s,
                  dynamicPhase: { ...s.dynamicPhase, status: "complete" },
                  agentReasoning: [...s.agentReasoning, "> Dynamic probing complete"],
                }));
              }
            }
            break;
          }

          case "finding": {
            const severity = (data.severity as string).toUpperCase() as Finding["severity"];
            const title = data.title as string;
            const ruleId = data.rule_id as string;
            const target = data.target as string | undefined;
            const source = data.source as string;

            const finding: Finding = {
              id: `${source}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
              severity,
              rule: ruleId,
              evidence: title,
              detail: target,
            };

            if (source === "static") {
              setState((s) => ({
                ...s,
                staticPhase: {
                  ...s.staticPhase,
                  findings: [...s.staticPhase.findings, finding],
                },
                agentReasoning: [...s.agentReasoning, `> ⚠ [${severity}] ${title}`],
              }));
            } else {
              setState((s) => ({
                ...s,
                dynamicPhase: {
                  ...s.dynamicPhase,
                  findings: [...s.dynamicPhase.findings, finding],
                },
                agentReasoning: [...s.agentReasoning, `> ⚠ [${severity}] ${title}`],
              }));
            }
            break;
          }

          case "tool_discovered": {
            const toolName = data.tool_name as string;
            const description = data.description as string | undefined;

            const tool: ToolProbeStatus = {
              name: toolName,
              description: description || "",
              status: "pending",
              findingCount: 0,
            };

            setState((s) => ({
              ...s,
              dynamicPhase: {
                ...s.dynamicPhase,
                tools: [...s.dynamicPhase.tools, tool],
              },
              agentReasoning: [...s.agentReasoning, `> Discovered tool: ${toolName}`],
            }));
            break;
          }

          case "tool_call": {
            const tool = data.tool as string;
            const input = data.input as Record<string, unknown>;
            const inputStr = JSON.stringify(input).slice(0, 100);

            setState((s) => ({
              ...s,
              dynamicPhase: {
                ...s.dynamicPhase,
                tools: s.dynamicPhase.tools.map((t) =>
                  t.name === tool ? { ...t, status: "probing" as const } : t
                ),
                logs: [...s.dynamicPhase.logs, `> ${tool}(${inputStr}${inputStr.length >= 100 ? "..." : ""})`],
              },
              agentReasoning: [...s.agentReasoning, `> Calling ${tool}...`],
            }));
            break;
          }

          case "agent_thought": {
            const text = data.text as string;
            if (text) {
              setState((s) => ({
                ...s,
                agentReasoning: [...s.agentReasoning, `> ${text.slice(0, 200)}${text.length > 200 ? "..." : ""}`],
              }));
            }
            break;
          }

          case "network_event": {
            const destination = data.destination as string;
            const port = data.port as number;
            const protocol = data.protocol as string;

            const event: NetworkEvent = {
              timestamp: new Date().toISOString(),
              destination,
              port,
              protocol: protocol.toUpperCase(),
              verdict: destination.includes("suspicious") ? "suspicious" : "expected",
            };

            setState((s) => ({
              ...s,
              networkLog: [...s.networkLog, event],
            }));
            break;
          }

          case "complete": {
            const verdict = (data.verdict as string).toUpperCase() as Verdict;
            const findingsCount = data.findings_count as number;

            setState((s) => ({
              ...s,
              agentReasoning: [...s.agentReasoning, `> Audit complete: ${verdict} (${findingsCount} findings)`],
            }));

            if (jobIdRef.current) {
              fetchFinalResult(jobIdRef.current);
            }
            break;
          }

          case "error": {
            const message = data.message as string;
            setState((s) => ({
              ...s,
              status: "error",
              agentReasoning: [...s.agentReasoning, `> ERROR: ${message}`],
            }));
            break;
          }
        }
      };

      const eventTypes = ["phase", "finding", "tool_discovered", "tool_call", "agent_thought", "network_event", "complete", "heartbeat"];
      
      eventTypes.forEach((eventType) => {
        eventSource.addEventListener(eventType, (e: MessageEvent) => {
          try {
            if (!e.data) return;
            const data = JSON.parse(e.data);
            handleEvent(eventType, data);
          } catch (err) {
            console.error(`Failed to parse ${eventType} event:`, err);
          }
        });
      });

      eventSource.addEventListener("error", (e: MessageEvent) => {
        // Only try to parse if there's actual data
        if (e.data && typeof e.data === 'string' && e.data.trim()) {
          try {
            const data = JSON.parse(e.data);
            handleEvent("error", data);
          } catch {
            // Ignore parse errors for error events
          }
        }
      });

      eventSource.onerror = (e: Event) => {
        console.log("SSE error:", e);
        if (eventSource.readyState === EventSource.CLOSED) {
          if (jobIdRef.current) {
            fetchFinalResult(jobIdRef.current);
          }
        }
      };

    } catch (error) {
      console.error("Failed to start audit:", error);
      setState((s) => ({
        ...s,
        status: "error",
        agentReasoning: [...s.agentReasoning, `> ERROR: ${error}`],
      }));
    }
  }, [fetchFinalResult]);

  const reset = useCallback(() => {
    closeEventSource();
    jobIdRef.current = null;
    setState(initialState());
  }, []);

  return { startAudit, state, reset };
}
