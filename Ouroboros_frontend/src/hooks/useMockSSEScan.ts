import { useCallback, useRef, useState } from "react";
import type { ActiveScan, TargetMode, WsEvent } from "@/types/ouroboros";
import { generateMockCall } from "./useMockWebSocket";

interface UseMockSSEScanReturn {
  scan: (target: string, targetType: TargetMode, toolName?: string) => void;
  activeScan: ActiveScan | null;
  isScanning: boolean;
}

export function useMockSSEScan(): UseMockSSEScanReturn {
  const [activeScan, setActiveScan] = useState<ActiveScan | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);

  const scan = useCallback(
    (target: string, targetType: TargetMode, toolName?: string) => {
      // Clear previous
      timeoutsRef.current.forEach(clearTimeout);
      timeoutsRef.current = [];

      const { events, timings } = generateMockCall();
      const id = (events[0] as { id: string }).id;

      const initial: ActiveScan = {
        id,
        target,
        targetType,
        toolName,
        timestamp: new Date().toISOString(),
        steps: [],
        findings: [],
        complete: false,
      };

      setActiveScan(initial);
      setIsScanning(true);

      events.forEach((evt: WsEvent, i: number) => {
        const t = setTimeout(() => {
          setActiveScan((prev) => {
            if (!prev) return prev;
            const next = { ...prev, steps: [...prev.steps], findings: [...prev.findings] };

            switch (evt.type) {
              case "probe_result":
                next.steps.push({
                  id: crypto.randomUUID(),
                  name: evt.probe,
                  duration_ms: evt.duration_ms,
                  status: "complete",
                  detail: evt.detail,
                  findings: evt.findings,
                });
                next.findings.push(...evt.findings);
                break;
              case "escalation_start":
                next.steps.push({
                  id: crypto.randomUUID(),
                  name: "ESCALATE",
                  duration_ms: 0,
                  status: "running",
                  detail: ["LLM analysis triggered by flagged content"],
                  findings: [],
                  isEscalation: true,
                  escalationText: "",
                  escalationStreaming: true,
                });
                break;
              case "escalation_chunk": {
                const escIdx = next.steps.findIndex((s) => s.isEscalation);
                if (escIdx >= 0) {
                  next.steps[escIdx] = {
                    ...next.steps[escIdx],
                    escalationText: (next.steps[escIdx].escalationText || "") + evt.text,
                  };
                }
                break;
              }
              case "escalation_end": {
                const escIdx2 = next.steps.findIndex((s) => s.isEscalation);
                if (escIdx2 >= 0) {
                  next.steps[escIdx2] = {
                    ...next.steps[escIdx2],
                    status: "complete",
                    duration_ms: evt.duration_ms,
                    escalationStreaming: false,
                  };
                }
                break;
              }
              case "verdict":
                next.verdict = evt.verdict.verdict;
                next.action = evt.verdict.action;
                next.totalDuration_ms = evt.verdict.totalDuration_ms;
                next.complete = true;
                setIsScanning(false);
                break;
            }
            return next;
          });
        }, timings[i]);
        timeoutsRef.current.push(t);
      });
    },
    []
  );

  return { scan, activeScan, isScanning };
}
