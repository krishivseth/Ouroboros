import { useState } from "react";
import { ChevronRight } from "lucide-react";
import type { Finding } from "@/types/ouroboros";
import { cn } from "@/lib/utils";

const severityColor: Record<string, string> = {
  CRITICAL: "text-signal-block",
  HIGH: "text-signal-block",
  MEDIUM: "text-signal-caution",
  LOW: "text-muted-foreground",
};

interface FindingsTableProps {
  findings: Finding[];
  highlightFindingId?: string | null;
  onFindingHover?: (id: string | null) => void;
}

export function FindingsTable({
  findings,
  highlightFindingId,
  onFindingHover,
}: FindingsTableProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (findings.length === 0) return null;

  return (
    <div className="border border-border rounded overflow-hidden">
      <table className="w-full text-xs font-mono">
        <thead>
          <tr className="border-b border-border bg-secondary/30">
            <th className="text-left px-3 py-1.5 text-muted-foreground font-medium w-8" />
            <th className="text-left px-3 py-1.5 text-muted-foreground font-medium w-20">
              Severity
            </th>
            <th className="text-left px-3 py-1.5 text-muted-foreground font-medium">
              Rule
            </th>
            <th className="text-left px-3 py-1.5 text-muted-foreground font-medium">
              Evidence
            </th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.id}
              onMouseEnter={() => onFindingHover?.(f.id)}
              onMouseLeave={() => onFindingHover?.(null)}
            >
              <td
                colSpan={4}
                className={cn(
                  "p-0 transition-colors",
                  highlightFindingId === f.id && "bg-signal-caution/5"
                )}
              >
                <button
                  onClick={() =>
                    setExpandedId(expandedId === f.id ? null : f.id)
                  }
                  className="flex items-center w-full text-left hover:bg-secondary/20 transition-colors"
                >
                  <span className="px-3 py-1.5 w-8">
                    <ChevronRight
                      className={cn(
                        "w-3 h-3 text-muted-foreground transition-transform",
                        expandedId === f.id && "rotate-90"
                      )}
                    />
                  </span>
                  <span
                    className={cn(
                      "px-3 py-1.5 w-20",
                      severityColor[f.severity]
                    )}
                  >
                    {f.severity}
                  </span>
                  <span className="px-3 py-1.5 text-foreground flex-1">
                    {f.rule}
                  </span>
                  <span className="px-3 py-1.5 text-muted-foreground flex-1 truncate">
                    {f.evidence}
                  </span>
                </button>
                {expandedId === f.id && (
                  <div className="px-3 pb-2 pl-11 text-[11px] text-muted-foreground">
                    {f.detail || f.evidence || "No additional details available"}
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
