import { useRef, useEffect, useState, useCallback } from "react";
import { ArrowDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface ContainerLogsProps {
  logs: string[];
  className?: string;
}

export function ContainerLogs({ logs, className }: ContainerLogsProps) {
  const containerRef = useRef<HTMLPreElement>(null);
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
  }, [logs, isAtBottom]);

  if (logs.length === 0) return null;

  return (
    <div className={cn("relative", className)}>
      <pre
        ref={containerRef}
        onScroll={handleScroll}
        className="p-3 bg-background rounded border border-border font-mono text-[11px] text-muted-foreground max-h-48 overflow-y-auto scrollbar-thin whitespace-pre-wrap"
      >
        {logs.map((line, i) => (
          <div
            key={i}
            className={cn(
              line.includes("⚠") && "text-signal-caution",
              line.includes("✗") && "text-signal-block",
              line.startsWith("$") && "text-foreground"
            )}
          >
            {line}
          </div>
        ))}
      </pre>
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
          Resume
        </button>
      )}
    </div>
  );
}
