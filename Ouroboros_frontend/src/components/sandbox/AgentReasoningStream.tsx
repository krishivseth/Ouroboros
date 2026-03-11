import { useRef, useEffect, useState, useCallback } from "react";
import { ArrowDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface AgentReasoningStreamProps {
  lines: string[];
  isStreaming: boolean;
}

export function AgentReasoningStream({ lines, isStreaming }: AgentReasoningStreamProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [isAtBottom, setIsAtBottom] = useState(true);

  const handleScroll = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    setIsAtBottom(el.scrollHeight - el.scrollTop - el.clientHeight < 30);
  }, []);

  useEffect(() => {
    if (isAtBottom && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines, isAtBottom]);

  if (lines.length === 0) return null;

  return (
    <div className="relative">
      <h4 className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground mb-2">
        Agent Reasoning
      </h4>
      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="p-3 bg-card rounded border border-border max-h-56 overflow-y-auto scrollbar-thin"
      >
        {lines.map((line, i) => (
          <div
            key={i}
            className={cn(
              "font-mono text-xs leading-relaxed",
              line.includes("⚠") ? "text-signal-caution" : line.includes("✗") ? "text-signal-block" : "text-muted-foreground"
            )}
          >
            {line}
          </div>
        ))}
        {isStreaming && (
          <span className="streaming-cursor font-mono text-xs text-signal-safe" />
        )}
      </div>
      {!isAtBottom && (
        <button
          onClick={() => {
            if (containerRef.current) {
              containerRef.current.scrollTop = containerRef.current.scrollHeight;
            }
          }}
          className="absolute bottom-2 right-2 flex items-center gap-1 font-mono text-[10px] text-foreground bg-accent px-2 py-1 rounded"
        >
          <ArrowDown className="w-3 h-3" />
          Resume Live
        </button>
      )}
    </div>
  );
}
