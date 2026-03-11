import type { RuntimeVerdict } from "@/types/ouroboros";
import { VerdictBadge } from "./VerdictBadge";
import { formatTimestamp, formatDuration, truncateUrl } from "@/utils/formatters";
import { cn } from "@/lib/utils";

interface FeedRowProps {
  item: RuntimeVerdict;
  selected: boolean;
  onClick: () => void;
  isNew?: boolean;
}

export function FeedRow({ item, selected, onClick, isNew }: FeedRowProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "w-full text-left px-3 py-2 border-l-[3px] border-b border-b-border transition-colors",
        selected
          ? "bg-accent border-l-foreground/40"
          : "border-l-transparent hover:bg-secondary/40",
        isNew && "slide-in-top",
        isNew && item.verdict === "BLOCK" && "block-pulse"
      )}
    >
      <div className="flex items-center gap-2">
        <span className="font-mono text-[10px] text-muted-foreground shrink-0 w-[76px]">
          {formatTimestamp(item.timestamp)}
        </span>
        <span
          className="font-mono text-xs text-foreground truncate flex-1"
          title={item.target}
        >
          {truncateUrl(item.target, 40)}
        </span>
        <VerdictBadge verdict={item.verdict} size="sm" />
      </div>
      <div className="flex items-center gap-3 mt-0.5 ml-[76px] pl-2">
        <span className="font-mono text-[10px] text-muted-foreground">
          {item.action}
        </span>
        <span className="font-mono text-[10px] text-muted-foreground">
          {formatDuration(item.totalDuration_ms)}
        </span>
        {item.findings.length > 0 && (
          <span className="font-mono text-[10px] text-signal-caution/70">
            {item.findings.length} finding{item.findings.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>
    </button>
  );
}
