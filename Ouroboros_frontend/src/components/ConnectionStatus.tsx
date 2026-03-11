import { cn } from "@/lib/utils";

interface ConnectionStatusProps {
  connected: boolean;
  className?: string;
}

export function ConnectionStatus({ connected, className }: ConnectionStatusProps) {
  return (
    <div className={cn("flex items-center gap-1.5", className)}>
      <div
        className={cn(
          "w-2 h-2 rounded-full",
          connected ? "bg-signal-safe animate-pulse" : "bg-signal-block"
        )}
      />
      <span className="font-mono text-[11px] text-muted-foreground">
        {connected ? "Connected" : "Disconnected"}
      </span>
    </div>
  );
}
