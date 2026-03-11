import { useState } from "react";
import { ChevronDown, ChevronRight, Check, AlertTriangle } from "lucide-react";
import type { NetworkEvent } from "@/types/sandbox";
import { cn } from "@/lib/utils";

interface NetworkActivityLogProps {
  events: NetworkEvent[];
}

export function NetworkActivityLog({ events }: NetworkActivityLogProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border rounded bg-card">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 hover:bg-accent/30 transition-colors"
      >
        {expanded ? (
          <ChevronDown className="w-3 h-3 text-muted-foreground" />
        ) : (
          <ChevronRight className="w-3 h-3 text-muted-foreground" />
        )}
        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Network Activity
        </span>
        <span className="font-mono text-[10px] text-muted-foreground ml-auto">
          {events.length === 0
            ? "No connections"
            : `${events.length} connection${events.length > 1 ? "s" : ""}`}
        </span>
      </button>

      {expanded && (
        <div className="border-t border-border">
          {events.length === 0 ? (
            <div className="px-3 py-3 font-mono text-xs text-signal-safe flex items-center gap-2">
              <Check className="w-3 h-3" />
              No outbound connections detected
            </div>
          ) : (
            <div>
              {/* Header */}
              <div className="grid grid-cols-[1fr_60px_60px_80px] gap-2 px-3 py-1.5 bg-secondary/40 border-b border-border">
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Destination</span>
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Port</span>
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Proto</span>
                <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Verdict</span>
              </div>
              {events.map((event, i) => (
                <div
                  key={i}
                  className={cn(
                    "grid grid-cols-[1fr_60px_60px_80px] gap-2 px-3 py-1.5 border-b border-border/50",
                    event.verdict === "suspicious" && "bg-signal-block/5"
                  )}
                >
                  <span className="font-mono text-[11px] text-foreground truncate">{event.destination}</span>
                  <span className="font-mono text-[11px] text-muted-foreground">{event.port}</span>
                  <span className="font-mono text-[11px] text-muted-foreground">{event.protocol}</span>
                  <span className="flex items-center gap-1">
                    {event.verdict === "expected" ? (
                      <Check className="w-3 h-3 text-signal-safe" />
                    ) : (
                      <AlertTriangle className="w-3 h-3 text-signal-caution" />
                    )}
                    <span
                      className={cn(
                        "font-mono text-[10px]",
                        event.verdict === "expected" ? "text-signal-safe" : "text-signal-caution"
                      )}
                    >
                      {event.verdict}
                    </span>
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
