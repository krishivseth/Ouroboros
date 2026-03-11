import { useState } from "react";
import { Scan } from "lucide-react";
import type { TargetMode } from "@/types/ouroboros";
import { cn } from "@/lib/utils";

interface ScanInputProps {
  onScan: (target: string, targetType: TargetMode, toolName?: string) => void;
  isScanning: boolean;
}

export function ScanInput({ onScan, isScanning }: ScanInputProps) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<TargetMode>("url");
  const [toolName, setToolName] = useState("");
  const [params, setParams] = useState("{}");

  const handleScan = () => {
    if (!target.trim()) return;
    onScan(target.trim(), mode, mode === "mcp" ? toolName.trim() : undefined);
  };

  return (
    <div className="space-y-3">
      {/* Mode toggle */}
      <div className="flex items-center gap-2">
        <div className="flex bg-secondary rounded-md p-0.5">
          <button
            onClick={() => setMode("url")}
            className={cn(
              "font-mono text-[11px] font-medium px-3 py-1 rounded transition-colors",
              mode === "url"
                ? "bg-accent text-foreground"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            URL Scan
          </button>
          <button
            onClick={() => setMode("mcp")}
            className={cn(
              "font-mono text-[11px] font-medium px-3 py-1 rounded transition-colors",
              mode === "mcp"
                ? "bg-accent text-foreground"
                : "text-muted-foreground hover:text-foreground"
            )}
          >
            MCP Tool
          </button>
        </div>
      </div>

      {/* URL input */}
      <div className="flex gap-2">
        <input
          type="text"
          placeholder={
            mode === "url"
              ? "https://api.example.com/endpoint"
              : "tool_name"
          }
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleScan()}
          className="flex-1 bg-secondary/50 border border-border rounded px-3 py-2 font-mono text-sm text-foreground placeholder:text-muted-foreground outline-none focus:border-signal-safe/40 transition-colors"
        />
        <button
          onClick={handleScan}
          disabled={isScanning || !target.trim()}
          className={cn(
            "flex items-center gap-2 px-4 py-2 rounded font-mono text-xs font-semibold transition-colors",
            isScanning
              ? "bg-signal-caution/20 text-signal-caution cursor-wait"
              : "bg-signal-safe/15 text-signal-safe border border-signal-safe/30 hover:bg-signal-safe/25"
          )}
        >
          <Scan className={cn("w-4 h-4", isScanning && "animate-spin")} />
          {isScanning ? "Scanning..." : "Scan"}
        </button>
      </div>

      {/* MCP extra fields */}
      {mode === "mcp" && (
        <div className="space-y-2">
          <input
            type="text"
            placeholder="Tool name (e.g., web_search)"
            value={toolName}
            onChange={(e) => setToolName(e.target.value)}
            className="w-full bg-secondary/50 border border-border rounded px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground outline-none focus:border-signal-safe/40 transition-colors"
          />
          <textarea
            placeholder='Input params (JSON): {"query": "test"}'
            value={params}
            onChange={(e) => setParams(e.target.value)}
            rows={3}
            className="w-full bg-secondary/50 border border-border rounded px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground outline-none focus:border-signal-safe/40 transition-colors resize-none"
          />
        </div>
      )}
    </div>
  );
}
