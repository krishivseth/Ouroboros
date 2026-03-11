import type { Verdict } from "@/types/ouroboros";
import { cn } from "@/lib/utils";

const variantMap: Record<Verdict, string> = {
  SAFE: "bg-signal-safe/15 text-signal-safe border-signal-safe/30",
  CAUTION: "bg-signal-caution/15 text-signal-caution border-signal-caution/30",
  BLOCK: "bg-signal-block/15 text-signal-block border-signal-block/30",
};

interface VerdictBadgeProps {
  verdict: Verdict;
  size?: "sm" | "md" | "lg";
  animate?: boolean;
  className?: string;
}

export function VerdictBadge({ verdict, size = "sm", animate = false, className }: VerdictBadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center font-mono font-semibold border rounded-full uppercase tracking-wider",
        variantMap[verdict],
        size === "sm" && "text-[10px] px-2 py-0.5",
        size === "md" && "text-xs px-3 py-1",
        size === "lg" && "text-sm px-4 py-1.5",
        animate && "verdict-animate",
        className
      )}
    >
      {verdict}
    </span>
  );
}
