import { useState } from "react";
import type { RuntimeVerdict } from "@/types/ouroboros";
import { VerdictBadge } from "./VerdictBadge";
import { ReasoningChain } from "./ReasoningChain";
import { FindingsTable } from "./FindingsTable";
import { RawDataView } from "./RawDataView";
import { formatTimestamp, formatDuration } from "@/utils/formatters";
import { cn } from "@/lib/utils";

interface DetailPanelProps {
  item: RuntimeVerdict | null;
  className?: string;
}

export function DetailPanel({ item, className }: DetailPanelProps) {
  const [highlightFindingId, setHighlightFindingId] = useState<string | null>(null);

  if (!item) {
    return (
      <div className={cn("flex items-center justify-center h-full", className)}>
        <div className="text-center">
          <p className="font-mono text-xs text-muted-foreground">
            Select an intercepted call to inspect
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className={cn("overflow-y-auto scrollbar-thin p-4 space-y-4", className)}>
      {/* Target Summary */}
      <div className="space-y-2">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="font-mono text-xs text-muted-foreground">
              {item.targetType === "mcp" ? "MCP Tool Call" : "HTTP Endpoint"}
            </p>
            <p className="font-mono text-sm text-foreground break-all">
              {item.target}
            </p>
          </div>
          <VerdictBadge
            verdict={item.verdict}
            size="lg"
            animate
          />
        </div>

        <div className="flex items-center gap-4 font-mono text-[11px] text-muted-foreground">
          <span>{formatTimestamp(item.timestamp)}</span>
          <span>{formatDuration(item.totalDuration_ms)}</span>
          <span>
            {item.action}
            {item.policyRule && (
              <span className="text-foreground/50"> · {item.policyRule}</span>
            )}
          </span>
        </div>
      </div>

      {/* Reasoning Chain */}
      <div>
        <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
          Reasoning Chain
        </h3>
        <div className={cn(
          "rounded border border-border bg-secondary/20 px-3",
          item.verdict === "BLOCK" && "vignette-block"
        )}>
          <ReasoningChain
            steps={item.steps}
            verdict={item.verdict}
            highlightFindingId={highlightFindingId}
            onFindingHover={setHighlightFindingId}
          />
        </div>
      </div>

      {/* Findings */}
      {item.findings.length > 0 && (
        <div>
          <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
            Findings ({item.findings.length})
          </h3>
          <FindingsTable
            findings={item.findings}
            highlightFindingId={highlightFindingId}
            onFindingHover={setHighlightFindingId}
          />
        </div>
      )}

      {/* Raw Data */}
      <div>
        <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
          Raw Data
        </h3>
        <RawDataView
          requestJson={item.requestJson}
          responseJson={item.responseJson}
          policyApplied={item.policyApplied}
        />
      </div>
    </div>
  );
}
