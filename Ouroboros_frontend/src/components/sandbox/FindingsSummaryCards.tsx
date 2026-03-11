import type { Finding } from "@/types/ouroboros";
import type { NetworkEvent } from "@/types/sandbox";
import { cn } from "@/lib/utils";

interface FindingsSummaryCardsProps {
  staticFindings: Finding[];
  dynamicFindings: Finding[];
  networkEvents: NetworkEvent[];
}

function countBySeverity(findings: Finding[]) {
  const counts: Record<string, number> = {};
  findings.forEach((f) => {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  });
  return counts;
}

function SeverityLine({ severity, count }: { severity: string; count: number }) {
  const color = severity === "CRITICAL" ? "text-signal-block" : severity === "HIGH" ? "text-signal-caution" : "text-muted-foreground";
  return (
    <div className={cn("font-mono text-[10px]", color)}>
      {severity === "CRITICAL" || severity === "HIGH" ? "⚠" : " "} {count} {severity}
    </div>
  );
}

export function FindingsSummaryCards({ staticFindings, dynamicFindings, networkEvents }: FindingsSummaryCardsProps) {
  const staticCounts = countBySeverity(staticFindings);
  const dynamicCounts = countBySeverity(dynamicFindings);
  const suspiciousCount = networkEvents.filter((e) => e.verdict === "suspicious").length;

  const cards = [
    {
      title: "STATIC",
      total: staticFindings.length,
      counts: staticCounts,
      clean: staticFindings.length === 0,
    },
    {
      title: "DYNAMIC",
      total: dynamicFindings.length,
      counts: dynamicCounts,
      clean: dynamicFindings.length === 0,
    },
    {
      title: "NETWORK",
      total: suspiciousCount,
      counts: {},
      clean: suspiciousCount === 0,
      customLabel: suspiciousCount === 0 ? "✓ Clean" : `⚠ ${suspiciousCount} suspicious`,
    },
  ];

  return (
    <div className="flex gap-3">
      {cards.map((card, i) => (
        <div
          key={card.title}
          className="flex-1 border border-border rounded p-3 bg-card"
          style={{ animationDelay: `${i * 100}ms` }}
        >
          <div className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-1">
            {card.title}
          </div>
          <div className="font-mono text-sm text-foreground">
            {card.customLabel
              ? card.customLabel
              : `${card.total} finding${card.total !== 1 ? "s" : ""}`}
          </div>
          {Object.entries(card.counts).map(([sev, count]) => (
            <SeverityLine key={sev} severity={sev} count={count} />
          ))}
          {card.clean && !card.customLabel && (
            <div className="font-mono text-[10px] text-signal-safe">✓ Clean</div>
          )}
        </div>
      ))}
    </div>
  );
}
