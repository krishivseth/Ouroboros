import type { AuditReport as AuditReportType } from "@/types/sandbox";
import { VerdictBadge } from "@/components/VerdictBadge";
import { FindingsSummaryCards } from "./FindingsSummaryCards";
import { UnifiedFindingsTable } from "./UnifiedFindingsTable";
import { AttackNarrative } from "./AttackNarrative";
import { NetworkActivityLog } from "./NetworkActivityLog";
import { formatDuration } from "@/utils/formatters";
import { Download, RotateCcw, Plus } from "lucide-react";
import { cn } from "@/lib/utils";

interface AuditReportProps {
  report: AuditReportType;
  onRerun: () => void;
  onNewAudit: () => void;
}

export function AuditReport({ report, onRerun, onNewAudit }: AuditReportProps) {
  const handleExport = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ouroboros-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-xs text-muted-foreground">Sandbox Audit Report</p>
          <p className="font-mono text-sm text-foreground break-all">{report.target}</p>
          <p className="font-mono text-[10px] text-muted-foreground mt-1">
            Duration: {formatDuration(report.duration_ms)} · {report.toolsDiscovered.length} tools audited
          </p>
        </div>
        <div className="flex items-center gap-2">
          <VerdictBadge verdict={report.overallVerdict} size="lg" animate />
        </div>
      </div>

      {/* Action buttons */}
      <div className="flex gap-2">
        <button
          onClick={onNewAudit}
          className={cn(
            "flex items-center gap-1.5 font-mono text-[11px] px-3 py-1.5 rounded",
            "bg-signal-safe text-primary-foreground hover:opacity-90 transition-opacity"
          )}
        >
          <Plus className="w-3 h-3" />
          New Audit
        </button>
        <button
          onClick={handleExport}
          className={cn(
            "flex items-center gap-1.5 font-mono text-[11px] px-3 py-1.5 rounded",
            "border border-border bg-secondary text-foreground hover:bg-accent transition-colors"
          )}
        >
          <Download className="w-3 h-3" />
          Export Report
        </button>
        <button
          onClick={onRerun}
          className={cn(
            "flex items-center gap-1.5 font-mono text-[11px] px-3 py-1.5 rounded",
            "border border-border bg-secondary text-foreground hover:bg-accent transition-colors"
          )}
        >
          <RotateCcw className="w-3 h-3" />
          Re-run Audit
        </button>
      </div>

      {/* Summary cards */}
      <FindingsSummaryCards
        staticFindings={report.staticFindings}
        dynamicFindings={report.dynamicFindings}
        networkEvents={report.networkEvents}
      />

      {/* Unified findings table */}
      <div>
        <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
          All Findings ({report.staticFindings.length + report.dynamicFindings.length})
        </h3>
        <UnifiedFindingsTable
          staticFindings={report.staticFindings}
          dynamicFindings={report.dynamicFindings}
        />
      </div>

      {/* Attack narrative */}
      <AttackNarrative narrative={report.narrative} />

      {/* Network activity */}
      <NetworkActivityLog events={report.networkEvents} />
    </div>
  );
}
