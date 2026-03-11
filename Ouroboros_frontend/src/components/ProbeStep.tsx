import { useState } from "react";
import { ChevronRight, Check, AlertTriangle, X } from "lucide-react";
import type { ProbeStepData } from "@/types/ouroboros";
import { formatDuration } from "@/utils/formatters";
import { cn } from "@/lib/utils";

interface ProbeStepProps {
  step: ProbeStepData;
  isLast?: boolean;
  verdictColor?: string;
  highlightFindingId?: string | null;
  onFindingHover?: (id: string | null) => void;
}

export function ProbeStep({
  step,
  isLast = false,
  verdictColor = "border-muted-foreground/30",
  highlightFindingId,
  onFindingHover,
}: ProbeStepProps) {
  const [expanded, setExpanded] = useState(true);
  const hasFindings = step.findings.length > 0;

  return (
    <div className="flex step-fade-in">
      {/* Timeline connector */}
      <div className="flex flex-col items-center mr-3 w-4 shrink-0">
        <div
          className={cn(
            "w-2 h-2 rounded-full mt-1.5 shrink-0",
            step.status === "running" && "bg-signal-caution animate-pulse",
            step.status === "complete" && !hasFindings && "bg-signal-safe",
            step.status === "complete" && hasFindings && "bg-signal-caution",
            step.status === "pending" && "bg-muted-foreground/40"
          )}
        />
        {!isLast && (
          <div className={cn("w-px flex-1 min-h-[16px]", verdictColor)} />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0 pb-3">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-2 w-full text-left group"
        >
          <ChevronRight
            className={cn(
              "w-3 h-3 text-muted-foreground transition-transform",
              expanded && "rotate-90"
            )}
          />
          <span className="font-mono text-xs font-semibold text-foreground">
            {step.name}
          </span>
          <span className="font-mono text-[10px] text-muted-foreground ml-auto">
            {step.status === "running" ? "..." : formatDuration(step.duration_ms)}
          </span>
        </button>

        {expanded && (
          <div className="mt-1.5 ml-5 space-y-0.5">
            {step.detail.map((line, i) => (
              <div
                key={i}
                className={cn(
                  "font-mono text-[11px] leading-relaxed",
                  line.startsWith("✓") && "text-signal-safe/80",
                  line.startsWith("✗") && "text-signal-block/80",
                  line.startsWith("⚠") && "text-signal-caution/80",
                  !line.startsWith("✓") && !line.startsWith("✗") && !line.startsWith("⚠") && "text-muted-foreground"
                )}
              >
                {line}
              </div>
            ))}

            {/* Escalation streaming text */}
            {step.isEscalation && step.escalationText && (
              <div className="mt-2 p-2 rounded bg-secondary/50 border border-border">
                <p
                  className={cn(
                    "font-mono text-[11px] text-foreground/80 leading-relaxed whitespace-pre-wrap",
                    step.escalationStreaming && "streaming-cursor"
                  )}
                >
                  "{step.escalationText}"
                </p>
              </div>
            )}

            {/* Inline findings */}
            {step.findings.map((f) => (
              <div
                key={f.id}
                onMouseEnter={() => onFindingHover?.(f.id)}
                onMouseLeave={() => onFindingHover?.(null)}
                className={cn(
                  "flex items-center gap-1.5 font-mono text-[11px] mt-1 px-1.5 py-0.5 rounded transition-colors",
                  highlightFindingId === f.id && "bg-signal-caution/10",
                  f.severity === "CRITICAL" || f.severity === "HIGH"
                    ? "text-signal-block/80"
                    : f.severity === "MEDIUM"
                    ? "text-signal-caution/80"
                    : "text-muted-foreground"
                )}
              >
                {f.severity === "CRITICAL" || f.severity === "HIGH" ? (
                  <X className="w-3 h-3" />
                ) : f.severity === "MEDIUM" ? (
                  <AlertTriangle className="w-3 h-3" />
                ) : (
                  <Check className="w-3 h-3" />
                )}
                <span>
                  {f.rule} ({f.severity})
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
