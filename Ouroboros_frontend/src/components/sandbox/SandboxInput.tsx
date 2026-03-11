import { useState } from "react";
import { Box, Play, Square } from "lucide-react";
import { cn } from "@/lib/utils";

interface SandboxInputProps {
  onStartAudit: (target: string, startCommand: string, baseImage: string) => void;
  onStopAudit?: () => void;
  isRunning: boolean;
}

const BASE_IMAGES = ["auto-detect", "node:20", "python:3.12"];

export function SandboxInput({ onStartAudit, onStopAudit, isRunning }: SandboxInputProps) {
  const [target, setTarget] = useState("");
  const [startCommand, setStartCommand] = useState("");
  const [baseImage, setBaseImage] = useState("auto-detect");

  const handleSubmit = () => {
    if (!target.trim() || isRunning) return;
    onStartAudit(target.trim(), startCommand.trim(), baseImage);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 mb-1">
        <Box className="w-4 h-4 text-signal-safe" />
        <h2 className="font-mono text-sm font-semibold text-foreground">
          Sandbox Audit
        </h2>
      </div>

      <div className="space-y-3">
        {/* Target */}
        <div>
          <label className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground block mb-1">
            Repository URL or Path
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="https://github.com/user/repo"
            disabled={isRunning}
            className={cn(
              "w-full font-mono text-sm bg-secondary border border-border rounded px-3 py-2",
              "text-foreground placeholder:text-muted-foreground",
              "focus:outline-none focus:ring-1 focus:ring-ring",
              "disabled:opacity-50"
            )}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          />
        </div>

        {/* Start command + Base image row */}
        <div className="flex gap-3">
          <div className="flex-1">
            <label className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground block mb-1">
              Start Command (optional)
            </label>
            <input
              type="text"
              value={startCommand}
              onChange={(e) => setStartCommand(e.target.value)}
              placeholder="npm start"
              disabled={isRunning}
              className={cn(
                "w-full font-mono text-sm bg-secondary border border-border rounded px-3 py-2",
                "text-foreground placeholder:text-muted-foreground",
                "focus:outline-none focus:ring-1 focus:ring-ring",
                "disabled:opacity-50"
              )}
            />
          </div>
          <div className="w-40">
            <label className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground block mb-1">
              Base Image
            </label>
            <select
              value={baseImage}
              onChange={(e) => setBaseImage(e.target.value)}
              disabled={isRunning}
              className={cn(
                "w-full font-mono text-sm bg-secondary border border-border rounded px-3 py-2",
                "text-foreground",
                "focus:outline-none focus:ring-1 focus:ring-ring",
                "disabled:opacity-50"
              )}
            >
              {BASE_IMAGES.map((img) => (
                <option key={img} value={img}>{img}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Begin/Stop Audit */}
        <div className="flex items-center gap-3">
          {isRunning ? (
            <button
              onClick={onStopAudit}
              className={cn(
                "flex items-center gap-2 font-mono text-xs font-medium px-4 py-2 rounded",
                "bg-signal-block text-primary-foreground",
                "hover:opacity-90 transition-opacity"
              )}
            >
              <Square className="w-3 h-3" />
              Stop Audit
            </button>
          ) : (
            <button
              onClick={handleSubmit}
              disabled={!target.trim()}
              className={cn(
                "flex items-center gap-2 font-mono text-xs font-medium px-4 py-2 rounded",
                "bg-signal-safe text-primary-foreground",
                "hover:opacity-90 transition-opacity",
                "disabled:opacity-40 disabled:cursor-not-allowed"
              )}
            >
              <Play className="w-3 h-3" />
              Begin Audit
            </button>
          )}
          <span className="font-mono text-[10px] text-muted-foreground">
            {isRunning ? "Audit in progress…" : "Typical audit: 1–3 minutes"}
          </span>
        </div>
      </div>
    </div>
  );
}
