import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Finding } from "@/types/ouroboros";
import { cn } from "@/lib/utils";

interface UnifiedFinding extends Finding {
  source: "Static" | "Dynamic";
  toolOrFile?: string;
  remediation?: string;
}

interface UnifiedFindingsTableProps {
  staticFindings: Finding[];
  dynamicFindings: Finding[];
}

const severityColor: Record<string, string> = {
  CRITICAL: "text-signal-block",
  HIGH: "text-signal-caution",
  MEDIUM: "text-muted-foreground",
  LOW: "text-muted-foreground",
};

const severityOrder: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
};

export function UnifiedFindingsTable({ staticFindings, dynamicFindings }: UnifiedFindingsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState<"severity" | "source">("severity");

  const unified: UnifiedFinding[] = [
    ...staticFindings.map((f) => ({ ...f, source: "Static" as const })),
    ...dynamicFindings.map((f) => ({ ...f, source: "Dynamic" as const })),
  ].sort((a, b) => {
    if (sortBy === "severity") return (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
    return a.source.localeCompare(b.source);
  });

  if (unified.length === 0) {
    return (
      <div className="font-mono text-xs text-muted-foreground text-center py-4">
        No findings detected ✓
      </div>
    );
  }

  return (
    <div className="border border-border rounded overflow-hidden">
      {/* Header */}
      <div className="grid grid-cols-[80px_70px_120px_1fr] gap-2 px-3 py-2 bg-secondary/40 border-b border-border">
        <button
          onClick={() => setSortBy("severity")}
          className={cn("font-mono text-[10px] uppercase tracking-widest text-left", sortBy === "severity" ? "text-foreground" : "text-muted-foreground")}
        >
          Severity
        </button>
        <button
          onClick={() => setSortBy("source")}
          className={cn("font-mono text-[10px] uppercase tracking-widest text-left", sortBy === "source" ? "text-foreground" : "text-muted-foreground")}
        >
          Source
        </button>
        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Rule</span>
        <span className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">Evidence</span>
      </div>

      {/* Rows */}
      {unified.map((f) => (
        <div key={f.id}>
          <button
            onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
            className="w-full grid grid-cols-[80px_70px_120px_1fr] gap-2 px-3 py-2 hover:bg-accent/30 transition-colors text-left border-b border-border/50"
          >
            <span className={cn("font-mono text-[11px] font-medium", severityColor[f.severity])}>
              {f.severity}
            </span>
            <span className="font-mono text-[11px] text-muted-foreground">{f.source}</span>
            <span className="font-mono text-[11px] text-foreground truncate">{f.rule}</span>
            <div className="flex items-center gap-1">
              <span className="font-mono text-[11px] text-muted-foreground truncate flex-1">
                {f.evidence}
              </span>
              {expandedId === f.id ? (
                <ChevronDown className="w-3 h-3 text-muted-foreground shrink-0" />
              ) : (
                <ChevronRight className="w-3 h-3 text-muted-foreground shrink-0" />
              )}
            </div>
          </button>
          {expandedId === f.id && f.detail && (
            <div className="px-3 py-2 bg-secondary/20 border-b border-border/50">
              <p className="font-mono text-[11px] text-muted-foreground whitespace-pre-wrap">
                {f.detail}
              </p>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
