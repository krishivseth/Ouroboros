export type Verdict = "SAFE" | "CAUTION" | "BLOCK";
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type EnforcementAction = "passed" | "warned" | "blocked";
export type TargetMode = "url" | "mcp";
export type AppMode = "monitor" | "scan" | "sandbox";

export interface Finding {
  id: string;
  severity: Severity;
  rule: string;
  evidence: string;
  detail?: string;
  probeStepId?: string;
}

export interface ProbeStepData {
  id: string;
  name: string;
  duration_ms: number;
  status: "pending" | "running" | "complete";
  detail: string[];
  findings: Finding[];
  isEscalation?: boolean;
  escalationText?: string;
  escalationStreaming?: boolean;
}

export interface RuntimeVerdict {
  id: string;
  target: string;
  targetType: TargetMode;
  toolName?: string;
  timestamp: string;
  verdict: Verdict;
  action: EnforcementAction;
  policyRule?: string;
  totalDuration_ms: number;
  steps: ProbeStepData[];
  findings: Finding[];
  requestJson?: string;
  responseJson?: string;
  policyApplied?: string;
}

export interface ActiveScan {
  id: string;
  target: string;
  targetType: TargetMode;
  toolName?: string;
  timestamp: string;
  steps: ProbeStepData[];
  findings: Finding[];
  verdict?: Verdict;
  action?: EnforcementAction;
  totalDuration_ms?: number;
  complete: boolean;
}

// WebSocket event types
export interface WsCallStart {
  type: "call_start";
  id: string;
  target: string;
  targetType: TargetMode;
  toolName?: string;
  timestamp: string;
}

export interface WsProbeResult {
  type: "probe_result";
  id: string;
  probe: string;
  duration_ms: number;
  findings: Finding[];
  detail: string[];
}

export interface WsEscalationStart {
  type: "escalation_start";
  id: string;
}

export interface WsEscalationChunk {
  type: "escalation_chunk";
  id: string;
  text: string;
}

export interface WsEscalationEnd {
  type: "escalation_end";
  id: string;
  duration_ms: number;
}

export interface WsVerdict {
  type: "verdict";
  id: string;
  verdict: RuntimeVerdict;
}

export type WsEvent =
  | WsCallStart
  | WsProbeResult
  | WsEscalationStart
  | WsEscalationChunk
  | WsEscalationEnd
  | WsVerdict;

export interface FeedFilters {
  verdicts: Verdict[];
  searchQuery: string;
  timeRange: "5m" | "15m" | "1h" | "all";
  ruleId?: string;
}
