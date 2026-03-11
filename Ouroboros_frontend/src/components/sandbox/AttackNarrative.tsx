import { cn } from "@/lib/utils";

interface AttackNarrativeProps {
  narrative: string;
}

function renderMarkdown(text: string) {
  return text.split("\n").map((line, i) => {
    // H2
    if (line.startsWith("## ")) {
      return (
        <h3 key={i} className="font-mono text-sm font-semibold text-foreground mt-4 mb-2">
          {line.slice(3)}
        </h3>
      );
    }
    // H3
    if (line.startsWith("### ")) {
      return (
        <h4 key={i} className="font-mono text-xs font-semibold text-foreground mt-3 mb-1">
          {line.slice(4)}
        </h4>
      );
    }
    // Numbered list
    if (/^\d+\.\s/.test(line)) {
      const match = line.match(/^(\d+\.)\s\*\*(.*?)\*\*:?\s*(.*)$/);
      if (match) {
        return (
          <div key={i} className="font-mono text-xs text-muted-foreground ml-3 mb-0.5">
            <span className="text-foreground">{match[1]}</span>{" "}
            <span className="font-semibold text-foreground">{match[2]}</span>
            {match[3] && <span>: {match[3]}</span>}
          </div>
        );
      }
      return (
        <div key={i} className="font-mono text-xs text-muted-foreground ml-3 mb-0.5">
          {line}
        </div>
      );
    }
    // Empty line
    if (line.trim() === "") return <div key={i} className="h-2" />;
    // Bold inline
    const parts = line.split(/(\*\*.*?\*\*)/g);
    return (
      <p key={i} className="font-mono text-xs text-muted-foreground mb-0.5">
        {parts.map((part, j) =>
          part.startsWith("**") && part.endsWith("**") ? (
            <span key={j} className="font-semibold text-foreground">
              {part.slice(2, -2)}
            </span>
          ) : (
            <span key={j}>{part}</span>
          )
        )}
      </p>
    );
  });
}

export function AttackNarrative({ narrative }: AttackNarrativeProps) {
  return (
    <div className="border border-border rounded p-4 bg-card">
      <h3 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-3">
        Attack Narrative
      </h3>
      <div>{renderMarkdown(narrative)}</div>
    </div>
  );
}
