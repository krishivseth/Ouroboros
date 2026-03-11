import { Check, Loader2, AlertTriangle, X } from "lucide-react";
import type { PhaseStep, PhaseStatus } from "@/types/sandbox";
import { cn } from "@/lib/utils";
import { useState } from "react";

interface PhaseColumnProps {
  title: string;
  status: PhaseStatus;
  steps: PhaseStep[];
  logs?: string[];
  extra?: React.ReactNode;
}

function StepIcon({ status }: { status: PhaseStep["status"] }) {
  switch (status) {
    case "complete":
      return <Check className="w-3 h-3 text-signal-safe" />;
    case "running":
      return <Loader2 className="w-3 h-3 text-signal-safe animate-spin" />;
    case "error":
      return <X className="w-3 h-3 text-signal-block" />;
    default:
      return <span className="w-3 h-3 rounded-full border border-muted-foreground inline-block" />;
  }
}

export function PhaseColumn({ title, status, steps, logs, extra }: PhaseColumnProps) {
  const [showLogs, setShowLogs] = useState(false);

  return (
    <div
      className={cn(
        "flex-1 border border-border rounded p-3 bg-card min-w-0",
        status === "running" && "phase-active-pulse"
      )}
    >
      <h4 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-3">
        {title}
      </h4>

      <div className="space-y-2">
        {steps.map((step) => (
          <div key={step.id} className="flex items-center gap-2">
            <StepIcon status={step.status} />
            <span
              className={cn(
                "font-mono text-xs",
                step.status === "complete" ? "text-foreground" : "text-muted-foreground",
                step.status === "error" && "text-signal-block"
              )}
            >
              {step.label}
            </span>
            {step.detail && (
              <span className="font-mono text-[10px] text-muted-foreground ml-auto">
                {step.detail}
              </span>
            )}
          </div>
        ))}
      </div>

      {extra}

      {logs && logs.length > 0 && (
        <div className="mt-3">
          <button
            onClick={() => setShowLogs(!showLogs)}
            className="font-mono text-[10px] text-muted-foreground hover:text-foreground transition-colors"
          >
            {showLogs ? "Hide Logs" : "View Logs"}
          </button>
          {showLogs && (
            <pre className="mt-2 p-2 bg-background rounded border border-border font-mono text-[10px] text-muted-foreground max-h-40 overflow-y-auto scrollbar-thin whitespace-pre-wrap">
              {logs.join("\n")}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
