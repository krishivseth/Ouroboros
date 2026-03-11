import { useReducer, useCallback, useRef, useState } from "react";
import type {
  RuntimeVerdict,
  FeedFilters,
  AppMode,
  ActiveScan,
  WsEvent,
  ProbeStepData,
} from "@/types/ouroboros";
import { TopBar } from "@/components/TopBar";
import { MonitorFeed } from "@/components/MonitorFeed";
import { DetailPanel } from "@/components/DetailPanel";
import { ScanInput } from "@/components/ScanInput";
import { ScanHistory } from "@/components/ScanHistory";
import { ReasoningChain } from "@/components/ReasoningChain";
import { VerdictBadge } from "@/components/VerdictBadge";
import { FindingsTable } from "@/components/FindingsTable";
import { RawDataView } from "@/components/RawDataView";
import { useMockWebSocket } from "@/hooks/useMockWebSocket";
import { useMonitorWebSocket } from "@/hooks/useMonitorWebSocket";
import { useMockSSEScan } from "@/hooks/useMockSSEScan";
import { useMockSandboxAudit } from "@/hooks/useMockSandboxAudit";
import { useSandboxAudit } from "@/hooks/useSandboxAudit";
import { useRuntimeScan } from "@/hooks/useRuntimeScan";
import { formatTimestamp, formatDuration } from "@/utils/formatters";
import { cn } from "@/lib/utils";

// Sandbox components
import { SandboxInput } from "@/components/sandbox/SandboxInput";
import { AuditProgress } from "@/components/sandbox/AuditProgress";
import { AuditReport } from "@/components/sandbox/AuditReport";

const MAX_FEED = 500;

type FeedAction =
  | { type: "ADD_VERDICT"; verdict: RuntimeVerdict }
  | { type: "UPDATE_CALL"; id: string; update: Partial<RuntimeVerdict> }
  | { type: "CLEAR" };

function feedReducer(state: RuntimeVerdict[], action: FeedAction): RuntimeVerdict[] {
  switch (action.type) {
    case "ADD_VERDICT":
      // Check if we already have this call in progress
      const existingIndex = state.findIndex(v => v.id === action.verdict.id);
      if (existingIndex >= 0) {
        // Merge with existing (keep accumulated steps)
        const existing = state[existingIndex];
        const merged = {
          ...action.verdict,
          steps: action.verdict.steps?.length ? action.verdict.steps : existing.steps,
        };
        const newState = [...state];
        newState[existingIndex] = merged;
        return newState;
      }
      return [action.verdict, ...state].slice(0, MAX_FEED);
    case "UPDATE_CALL": {
      const idx = state.findIndex(v => v.id === action.id);
      if (idx >= 0) {
        const newState = [...state];
        newState[idx] = { ...newState[idx], ...action.update };
        return newState;
      }
      return state;
    }
    case "CLEAR":
      return [];
    default:
      return state;
  }
}

const Index = () => {
  const [mode, setMode] = useState<AppMode>("monitor");
  const [feed, dispatchFeed] = useReducer(feedReducer, []);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filters, setFilters] = useState<FeedFilters>({
    verdicts: [],
    searchQuery: "",
    timeRange: "all",
  });
  const [newIds, setNewIds] = useState<Set<string>>(new Set());
  const newIdTimers = useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  // Determine if we should use real API
  const useRealApi = import.meta.env.VITE_USE_REAL_API === "true";

  // Scan mode state - use real API if VITE_USE_REAL_API is set to "true"
  const mockScan = useMockSSEScan();
  const realScan = useRuntimeScan();
  const { scan, activeScan, isScanning } = useRealApi ? realScan : mockScan;
  const [scanHistory, setScanHistory] = useState<ActiveScan[]>([]);
  const [viewingScan, setViewingScan] = useState<ActiveScan | null>(null);

  // Sandbox mode state - use real API if VITE_USE_REAL_API is set to "true", otherwise use mock
  const mockSandbox = useMockSandboxAudit();
  const realSandbox = useSandboxAudit();
  const { startAudit, state: sandboxState, reset: resetSandbox } = useRealApi ? realSandbox : mockSandbox;

  // Track in-progress calls for building up steps
  const inProgressCalls = useRef<Map<string, { steps: ProbeStepData[]; escalationText: string }>>(new Map());

  const handleWsEvent = useCallback((event: WsEvent) => {
    if (event.type === "call_start") {
      // Initialize a new call
      inProgressCalls.current.set(event.id, { steps: [], escalationText: "" });
      
      // Add placeholder to feed
      const placeholder: RuntimeVerdict = {
        id: event.id,
        target: event.target,
        targetType: event.targetType,
        toolName: event.toolName,
        timestamp: event.timestamp,
        verdict: "SAFE", // Will be updated
        action: "passed",
        totalDuration_ms: 0,
        steps: [],
        findings: [],
      };
      dispatchFeed({ type: "ADD_VERDICT", verdict: placeholder });
      
    } else if (event.type === "probe_result") {
      // Add step to in-progress call
      const call = inProgressCalls.current.get(event.id);
      if (call) {
        const step: ProbeStepData = {
          id: crypto.randomUUID(),
          name: event.probe,
          duration_ms: event.duration_ms,
          status: "complete",
          detail: event.detail || [],
          findings: event.findings || [],
        };
        call.steps.push(step);
        
        // Update the feed item with new steps
        dispatchFeed({
          type: "UPDATE_CALL",
          id: event.id,
          update: { steps: [...call.steps] },
        });
      }
      
    } else if (event.type === "escalation_start") {
      const call = inProgressCalls.current.get(event.id);
      if (call) {
        call.escalationText = "";
      }
      
    } else if (event.type === "escalation_chunk") {
      const call = inProgressCalls.current.get(event.id);
      if (call) {
        call.escalationText += event.text;
      }
      
    } else if (event.type === "escalation_end") {
      const call = inProgressCalls.current.get(event.id);
      if (call && call.escalationText) {
        // Add escalation as a step
        const escalationStep: ProbeStepData = {
          id: crypto.randomUUID(),
          name: "ESCALATE",
          duration_ms: event.duration_ms,
          status: "complete",
          detail: ["LLM analysis triggered"],
          findings: [],
          isEscalation: true,
          escalationText: call.escalationText,
        };
        call.steps.push(escalationStep);
        
        dispatchFeed({
          type: "UPDATE_CALL",
          id: event.id,
          update: { steps: [...call.steps] },
        });
      }
      
    } else if (event.type === "verdict") {
      const v = event.verdict;
      const call = inProgressCalls.current.get(v.id);
      
      // Merge accumulated steps with verdict
      const finalVerdict: RuntimeVerdict = {
        ...v,
        steps: call?.steps || v.steps || [],
      };
      
      dispatchFeed({ type: "ADD_VERDICT", verdict: finalVerdict });
      
      // Clean up
      inProgressCalls.current.delete(v.id);

      setNewIds((prev) => new Set(prev).add(v.id));
      const timer = setTimeout(() => {
        setNewIds((prev) => {
          const next = new Set(prev);
          next.delete(v.id);
          return next;
        });
      }, 2000);
      newIdTimers.current.set(v.id, timer);
    }
  }, []);

  // Always call the hook unconditionally (React rules of hooks)
  // Use real WebSocket when in real API mode, mock otherwise
  const mockWs = useMockWebSocket(handleWsEvent, mode === "monitor" && !useRealApi);
  const realWs = useMonitorWebSocket(handleWsEvent, mode === "monitor" && useRealApi);
  const { connected } = useRealApi ? realWs : mockWs;

  const selectedItem = feed.find((f) => f.id === selectedId) || null;

  const handleScan = (target: string, targetType: "url" | "mcp", toolName?: string) => {
    scan(target, targetType, toolName);
  };

  // When scan completes, add to history
  const prevComplete = useRef(false);
  if (activeScan?.complete && !prevComplete.current) {
    prevComplete.current = true;
    setScanHistory((prev) => [activeScan, ...prev]);
  }
  if (!activeScan?.complete) {
    prevComplete.current = false;
  }

  const displayedScan = viewingScan || activeScan;

  const handleStartAudit = (target: string, startCommand: string, baseImage: string) => {
    startAudit(target, startCommand, baseImage);
  };

  const handleRerunAudit = () => {
    const { target, startCommand, baseImage } = sandboxState;
    resetSandbox();
    setTimeout(() => startAudit(target, startCommand, baseImage), 100);
  };

  const handleNewAudit = () => {
    resetSandbox();
  };

  const handleStopAudit = () => {
    resetSandbox();
  };

  // Render content based on mode
  const renderContent = () => {
    if (mode === "monitor") {
      if (useRealApi && !connected) {
        return (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center max-w-md p-8">
              <div className="text-6xl mb-4">🔌</div>
              <h2 className="text-xl font-semibold text-foreground mb-2">No Proxy Connected</h2>
              <p className="text-muted-foreground mb-4">
                The Monitor tab shows real-time MCP traffic when the Ouroboros Runtime proxy is running.
              </p>
              <p className="text-sm text-muted-foreground">
                Start the proxy with: <code className="bg-muted px-2 py-1 rounded">ouroboros runtime proxy</code>
              </p>
              <p className="text-sm text-muted-foreground mt-4">
                Or switch to <strong>Sandbox</strong> mode to run security audits.
              </p>
            </div>
          </div>
        );
      }
      return (
        <div className="flex flex-1 min-h-0">
          <div className="w-[60%] border-r border-border relative">
            <MonitorFeed
              feed={feed}
              selectedId={selectedId}
              onSelect={(item) => setSelectedId(item.id)}
              filters={filters}
              onFiltersChange={setFilters}
              newIds={newIds}
            />
          </div>
          <div className="w-[40%] bg-card">
            <DetailPanel item={selectedItem} className="h-full" />
          </div>
        </div>
      );
    }

    if (mode === "scan") {
      return (
        <div className="flex-1 overflow-y-auto scrollbar-thin">
          <div className="max-w-3xl mx-auto p-6 space-y-6">
            <ScanInput onScan={handleScan} isScanning={isScanning} />

            {displayedScan && (
              <div className="space-y-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-mono text-xs text-muted-foreground">
                      {displayedScan.targetType === "mcp" ? "MCP Tool Call" : "HTTP Endpoint"}
                    </p>
                    <p className="font-mono text-sm text-foreground break-all">
                      {displayedScan.target}
                    </p>
                    <p className="font-mono text-[10px] text-muted-foreground mt-1">
                      {formatTimestamp(displayedScan.timestamp)}
                      {displayedScan.totalDuration_ms && (
                        <> · {formatDuration(displayedScan.totalDuration_ms)}</>
                      )}
                    </p>
                  </div>
                  {displayedScan.verdict && (
                    <VerdictBadge verdict={displayedScan.verdict} size="lg" animate />
                  )}
                </div>

                {displayedScan.steps.length > 0 && (
                  <div>
                    <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
                      Reasoning Chain
                    </h3>
                    <div className={cn(
                      "rounded border border-border bg-secondary/20 px-3",
                      displayedScan.verdict === "BLOCK" && displayedScan.complete && "vignette-block"
                    )}>
                      <ReasoningChain
                        steps={displayedScan.steps}
                        verdict={displayedScan.verdict}
                      />
                    </div>
                  </div>
                )}

                {displayedScan.findings.length > 0 && (
                  <div>
                    <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
                      Findings ({displayedScan.findings.length})
                    </h3>
                    <FindingsTable findings={displayedScan.findings} />
                  </div>
                )}
              </div>
            )}

            <ScanHistory
              scans={scanHistory}
              onSelect={(s) => setViewingScan(s)}
              selectedId={viewingScan?.id}
            />
          </div>
        </div>
      );
    }

    // Sandbox mode
    return (
      <div className="flex-1 overflow-y-auto scrollbar-thin">
        <div className="max-w-4xl mx-auto p-6 space-y-6">
          {(sandboxState.status === "idle" || sandboxState.status === "error") && (
            <SandboxInput onStartAudit={handleStartAudit} isRunning={false} />
          )}

          {sandboxState.status === "error" && (
            <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
              <p className="text-destructive font-medium">Audit failed</p>
              <p className="text-sm text-muted-foreground mt-1">
                {sandboxState.agentReasoning[sandboxState.agentReasoning.length - 1] || "Unknown error"}
              </p>
            </div>
          )}

          {sandboxState.status === "running" && (
            <>
              <SandboxInput onStartAudit={handleStartAudit} onStopAudit={handleStopAudit} isRunning={true} />
              <AuditProgress state={sandboxState} />
            </>
          )}

          {sandboxState.status === "complete" && sandboxState.report && (
            <AuditReport report={sandboxState.report} onRerun={handleRerunAudit} onNewAudit={handleNewAudit} />
          )}
        </div>
      </div>
    );
  };

  return (
    <div className="flex flex-col h-screen bg-background">
      <TopBar mode={mode} onModeChange={setMode} connected={connected} />
      {renderContent()}
    </div>
  );
};

export default Index;
