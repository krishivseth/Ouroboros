import type { ActiveScan } from "@/types/ouroboros";
import { VerdictBadge } from "./VerdictBadge";
import { formatTimestamp, truncateUrl } from "@/utils/formatters";
import { cn } from "@/lib/utils";

interface ScanHistoryProps {
  scans: ActiveScan[];
  onSelect: (scan: ActiveScan) => void;
  selectedId?: string;
}

export function ScanHistory({ scans, onSelect, selectedId }: ScanHistoryProps) {
  if (scans.length === 0) return null;

  return (
    <div className="border-t border-border">
      <div className="px-3 py-2">
        <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
          Scan History
        </h3>
      </div>
      <div className="max-h-40 overflow-y-auto scrollbar-thin">
        {scans.map((scan) => (
          <button
            key={scan.id}
            onClick={() => onSelect(scan)}
            className={cn(
              "w-full text-left px-3 py-1.5 flex items-center gap-2 hover:bg-secondary/40 transition-colors",
              selectedId === scan.id && "bg-accent"
            )}
          >
            <span className="font-mono text-[10px] text-muted-foreground shrink-0">
              {formatTimestamp(scan.timestamp)}
            </span>
            <span className="font-mono text-[11px] text-foreground truncate flex-1">
              {truncateUrl(scan.target, 30)}
            </span>
            {scan.verdict && <VerdictBadge verdict={scan.verdict} size="sm" />}
          </button>
        ))}
      </div>
    </div>
  );
}
