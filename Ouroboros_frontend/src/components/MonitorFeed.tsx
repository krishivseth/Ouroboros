import { useRef, useState, useEffect, useCallback } from "react";
import { Search, ArrowUp } from "lucide-react";
import type { RuntimeVerdict, FeedFilters, Verdict } from "@/types/ouroboros";
import { FeedRow } from "./FeedRow";
import { cn } from "@/lib/utils";

interface MonitorFeedProps {
  feed: RuntimeVerdict[];
  selectedId: string | null;
  onSelect: (item: RuntimeVerdict) => void;
  filters: FeedFilters;
  onFiltersChange: (filters: FeedFilters) => void;
  newIds: Set<string>;
}

const VERDICT_OPTIONS: Verdict[] = ["SAFE", "CAUTION", "BLOCK"];
const TIME_OPTIONS: FeedFilters["timeRange"][] = ["5m", "15m", "1h", "all"];

export function MonitorFeed({
  feed,
  selectedId,
  onSelect,
  filters,
  onFiltersChange,
  newIds,
}: MonitorFeedProps) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [isAtTop, setIsAtTop] = useState(true);

  const handleScroll = useCallback(() => {
    if (!scrollRef.current) return;
    setIsAtTop(scrollRef.current.scrollTop < 20);
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.addEventListener("scroll", handleScroll);
    return () => el.removeEventListener("scroll", handleScroll);
  }, [handleScroll]);

  const resumeLive = () => {
    scrollRef.current?.scrollTo({ top: 0, behavior: "smooth" });
  };

  const toggleVerdict = (v: Verdict) => {
    const next = filters.verdicts.includes(v)
      ? filters.verdicts.filter((x) => x !== v)
      : [...filters.verdicts, v];
    onFiltersChange({ ...filters, verdicts: next });
  };

  // Apply filters
  const filtered = feed.filter((item) => {
    if (filters.verdicts.length > 0 && !filters.verdicts.includes(item.verdict)) return false;
    if (filters.searchQuery) {
      const q = filters.searchQuery.toLowerCase();
      if (!item.target.toLowerCase().includes(q) && !(item.toolName?.toLowerCase().includes(q))) return false;
    }
    if (filters.timeRange !== "all") {
      const ms = { "5m": 300000, "15m": 900000, "1h": 3600000 }[filters.timeRange];
      if (Date.now() - new Date(item.timestamp).getTime() > ms) return false;
    }
    return true;
  });

  return (
    <div className="flex flex-col h-full">
      {/* Filter bar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-border bg-card shrink-0 flex-wrap">
        {/* Verdict chips */}
        <div className="flex gap-1">
          {VERDICT_OPTIONS.map((v) => (
            <button
              key={v}
              onClick={() => toggleVerdict(v)}
              className={cn(
                "font-mono text-[10px] px-2 py-0.5 rounded-full border transition-colors",
                filters.verdicts.includes(v)
                  ? v === "SAFE"
                    ? "border-signal-safe/50 bg-signal-safe/10 text-signal-safe"
                    : v === "CAUTION"
                    ? "border-signal-caution/50 bg-signal-caution/10 text-signal-caution"
                    : "border-signal-block/50 bg-signal-block/10 text-signal-block"
                  : "border-border text-muted-foreground hover:text-foreground"
              )}
            >
              {v}
            </button>
          ))}
        </div>

        {/* Search */}
        <div className="flex items-center gap-1 flex-1 min-w-[120px] bg-secondary/50 rounded px-2 py-1">
          <Search className="w-3 h-3 text-muted-foreground" />
          <input
            type="text"
            placeholder="Filter by URL or tool..."
            value={filters.searchQuery}
            onChange={(e) =>
              onFiltersChange({ ...filters, searchQuery: e.target.value })
            }
            className="bg-transparent font-mono text-[11px] text-foreground placeholder:text-muted-foreground outline-none flex-1"
          />
        </div>

        {/* Time range */}
        <div className="flex gap-1">
          {TIME_OPTIONS.map((t) => (
            <button
              key={t}
              onClick={() => onFiltersChange({ ...filters, timeRange: t })}
              className={cn(
                "font-mono text-[10px] px-1.5 py-0.5 rounded transition-colors",
                filters.timeRange === t
                  ? "bg-accent text-foreground"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* Feed */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto scrollbar-thin relative"
      >
        {filtered.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-muted-foreground font-mono text-xs">
            No intercepted calls
          </div>
        ) : (
          filtered.map((item) => (
            <FeedRow
              key={item.id}
              item={item}
              selected={selectedId === item.id}
              onClick={() => onSelect(item)}
              isNew={newIds.has(item.id)}
            />
          ))
        )}
      </div>

      {/* Resume Live button */}
      {!isAtTop && (
        <button
          onClick={resumeLive}
          className="absolute bottom-4 left-1/2 -translate-x-1/2 flex items-center gap-1.5 bg-accent border border-border rounded-full px-3 py-1.5 font-mono text-[11px] text-foreground shadow-lg hover:bg-accent/80 transition-colors z-10"
        >
          <ArrowUp className="w-3 h-3" />
          Resume Live
        </button>
      )}
    </div>
  );
}
