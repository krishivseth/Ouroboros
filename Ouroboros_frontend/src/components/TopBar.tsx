import { Shield, Settings, Box } from "lucide-react";
import type { AppMode } from "@/types/ouroboros";
import { ConnectionStatus } from "./ConnectionStatus";
import { cn } from "@/lib/utils";

interface TopBarProps {
  mode: AppMode;
  onModeChange: (mode: AppMode) => void;
  connected: boolean;
}

export function TopBar({ mode, onModeChange, connected }: TopBarProps) {
  return (
    <header className="flex items-center justify-between h-11 px-4 border-b border-border bg-card shrink-0">
      {/* Logo */}
      <div className="flex items-center gap-2">
        <Shield className="w-4 h-4 text-signal-safe" />
        <span className="font-mono text-sm font-bold tracking-tight text-foreground">
          OUROBOROS
        </span>
        <span className="font-mono text-[10px] text-muted-foreground tracking-widest ml-1">
          RUNTIME
        </span>
      </div>

      {/* Mode toggle */}
      <div className="flex items-center bg-secondary rounded-md p-0.5">
        <button
          onClick={() => onModeChange("monitor")}
          className={cn(
            "font-mono text-[11px] font-medium px-3 py-1 rounded transition-colors",
            mode === "monitor"
              ? "bg-accent text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          Monitor
        </button>
        <button
          onClick={() => onModeChange("scan")}
          className={cn(
            "font-mono text-[11px] font-medium px-3 py-1 rounded transition-colors",
            mode === "scan"
              ? "bg-accent text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          Scan
        </button>
        <button
          onClick={() => onModeChange("sandbox")}
          className={cn(
            "font-mono text-[11px] font-medium px-3 py-1 rounded transition-colors flex items-center gap-1",
            mode === "sandbox"
              ? "bg-accent text-foreground"
              : "text-muted-foreground hover:text-foreground"
          )}
        >
          <Box className="w-3 h-3" />
          Sandbox
        </button>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-3">
        <ConnectionStatus connected={connected} />
        <button className="text-muted-foreground hover:text-foreground transition-colors">
          <Settings className="w-4 h-4" />
        </button>
      </div>
    </header>
  );
}
