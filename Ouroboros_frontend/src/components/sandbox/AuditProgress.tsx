import type { SandboxState } from "@/types/sandbox";
import { PhaseColumn } from "./PhaseColumn";
import { AgentReasoningStream } from "./AgentReasoningStream";
import { Check, AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

interface AuditProgressProps {
  state: SandboxState;
}

function ToolsList({ tools }: { tools: SandboxState["dynamicPhase"]["tools"] }) {
  if (tools.length === 0) return null;
  return (
    <div className="mt-3 space-y-1">
      {tools.map((tool) => (
        <div key={tool.name} className="flex items-center gap-2">
          {tool.status === "complete" ? (
            tool.findingCount > 0 ? (
              <AlertTriangle className="w-3 h-3 text-signal-caution" />
            ) : (
              <Check className="w-3 h-3 text-signal-safe" />
            )
          ) : tool.status === "probing" ? (
            <Loader2 className="w-3 h-3 text-signal-safe animate-spin" />
          ) : (
            <span className="w-3 h-3 rounded-full border border-muted-foreground inline-block" />
          )}
          <span
            className={cn(
              "font-mono text-xs",
              tool.status === "complete" ? "text-foreground" : "text-muted-foreground"
            )}
          >
            {tool.name}
          </span>
          {tool.status === "probing" && (
            <span className="font-mono text-[10px] text-signal-safe ml-auto">←</span>
          )}
          {tool.status === "complete" && tool.findingCount > 0 && (
            <span className="font-mono text-[10px] text-signal-caution ml-auto">
              {tool.findingCount} finding{tool.findingCount > 1 ? "s" : ""}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

export function AuditProgress({ state }: AuditProgressProps) {
  const { staticPhase, containerPhase, dynamicPhase, agentReasoning } = state;

  return (
    <div className="space-y-4">
      {/* Three phase columns */}
      <div className="flex gap-3">
        <PhaseColumn
          title="Phase 1: Static"
          status={staticPhase.status}
          steps={staticPhase.steps}
        />
        <PhaseColumn
          title="Phase 2: Container"
          status={containerPhase.status}
          steps={containerPhase.steps}
          logs={containerPhase.logs}
        />
        <PhaseColumn
          title="Phase 3: Dynamic"
          status={dynamicPhase.status}
          steps={dynamicPhase.tools.length > 0
            ? [{ id: "d-tools", label: `${dynamicPhase.tools.length} tools discovered`, status: dynamicPhase.status === "complete" ? "complete" : "running" }]
            : [{ id: "d-waiting", label: "Waiting for container…", status: "pending" }]}
          logs={dynamicPhase.logs}
          extra={<ToolsList tools={dynamicPhase.tools} />}
        />
      </div>

      {/* Agent reasoning stream */}
      <AgentReasoningStream
        lines={agentReasoning}
        isStreaming={state.status === "running"}
      />
    </div>
  );
}
