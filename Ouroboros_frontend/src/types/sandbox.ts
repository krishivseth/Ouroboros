import type { Verdict, Finding } from "./ouroboros";

export type PhaseStatus = "pending" | "running" | "complete" | "error";

export interface PhaseStep {
  id: string;
  label: string;
  status: PhaseStatus;
  detail?: string;
}

export interface ToolProbeStatus {
  name: string;
  description: string;
  status: "pending" | "probing" | "complete";
  findingCount: number;
  duration_ms?: number;
}

export interface NetworkEvent {
  timestamp: string;
  destination: string;
  port: number;
  protocol: string;
  verdict: "expected" | "suspicious";
}

export interface AuditReport {
  target: string;
  duration_ms: number;
  overallVerdict: Verdict;
  staticFindings: Finding[];
  dynamicFindings: Finding[];
  networkEvents: NetworkEvent[];
  narrative: string;
  toolsDiscovered: string[];
}

export interface SandboxState {
  status: "idle" | "running" | "complete" | "error";
  target: string;
  startCommand: string;
  baseImage: string;
  staticPhase: {
    status: PhaseStatus;
    steps: PhaseStep[];
    findings: Finding[];
  };
  containerPhase: {
    status: PhaseStatus;
    steps: PhaseStep[];
    logs: string[];
    containerId: string | null;
  };
  dynamicPhase: {
    status: PhaseStatus;
    tools: ToolProbeStatus[];
    findings: Finding[];
    logs: string[];
  };
  agentReasoning: string[];
  networkLog: NetworkEvent[];
  report: AuditReport | null;
  overallVerdict: Verdict | null;
  duration_ms: number | null;
}
