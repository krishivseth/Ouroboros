import type { ProbeStepData, Verdict } from "@/types/ouroboros";
import { ProbeStep } from "./ProbeStep";
import { cn } from "@/lib/utils";

const verdictLineColor: Record<Verdict, string> = {
  SAFE: "border-signal-safe/40",
  CAUTION: "border-signal-caution/40",
  BLOCK: "border-signal-block/40",
};

interface ReasoningChainProps {
  steps: ProbeStepData[];
  verdict?: Verdict;
  highlightFindingId?: string | null;
  onFindingHover?: (id: string | null) => void;
  className?: string;
}

export function ReasoningChain({
  steps,
  verdict,
  highlightFindingId,
  onFindingHover,
  className,
}: ReasoningChainProps) {
  const lineColor = verdict
    ? verdictLineColor[verdict]
    : "border-muted-foreground/20";

  if (!steps || steps.length === 0) {
    return (
      <div className={cn("py-2 text-muted-foreground text-sm", className)}>
        No probe steps yet...
      </div>
    );
  }

  return (
    <div className={cn("py-2", className)}>
      {steps.map((step, i) => (
        <ProbeStep
          key={step.id}
          step={step}
          isLast={i === steps.length - 1}
          verdictColor={lineColor}
          highlightFindingId={highlightFindingId}
          onFindingHover={onFindingHover}
        />
      ))}
    </div>
  );
}
