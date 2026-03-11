import { useCallback, useRef, useState } from "react";
import type { ActiveScan, TargetMode, Finding, Verdict } from "@/types/ouroboros";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

interface UseRuntimeScanReturn {
  scan: (target: string, targetType: TargetMode, toolName?: string) => void;
  activeScan: ActiveScan | null;
  isScanning: boolean;
}

interface ProbeResultEvent {
  probe_id: string;
  duration_ms: number;
  findings_count: number;
  detail: string[];
  findings: Array<{
    rule_id: string;
    severity: string;
    title: string;
    evidence: string;
  }>;
}

interface VerdictEvent {
  verdict: string;
  findings_count: number;
  duration_ms: number;
}

export function useRuntimeScan(): UseRuntimeScanReturn {
  const [activeScan, setActiveScan] = useState<ActiveScan | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  const jobIdRef = useRef<string | null>(null);

  const closeEventSource = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
  }, []);

  const scan = useCallback(
    async (target: string, targetType: TargetMode, toolName?: string) => {
      closeEventSource();

      const scanId = crypto.randomUUID();
      const initial: ActiveScan = {
        id: scanId,
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

      try {
        const response = await fetch(`${API_URL}/api/runtime/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target_url: target,
            include_safebrowsing: true,
            include_virustotal: true,
          }),
        });

        if (!response.ok) {
          throw new Error(`Failed to start scan: ${response.statusText}`);
        }

        const data = await response.json();
        const jobId = data.job_id;
        jobIdRef.current = jobId;

        const eventSource = new EventSource(
          `${API_URL}/api/runtime/scan/${jobId}/stream`
        );
        eventSourceRef.current = eventSource;

        eventSource.addEventListener("probe_start", (e) => {
          const eventData = JSON.parse(e.data);
          setActiveScan((prev) => {
            if (!prev) return prev;
            const next = { ...prev, steps: [...prev.steps] };
            next.steps.push({
              id: crypto.randomUUID(),
              name: eventData.probe_id,
              duration_ms: 0,
              status: "running",
              detail: [],
              findings: [],
            });
            return next;
          });
        });

        eventSource.addEventListener("probe_result", (e) => {
          const eventData: ProbeResultEvent = JSON.parse(e.data);
          setActiveScan((prev) => {
            if (!prev) return prev;
            const next = {
              ...prev,
              steps: [...prev.steps],
              findings: [...prev.findings],
            };

            const stepIdx = next.steps.findIndex(
              (s) => s.name === eventData.probe_id && s.status === "running"
            );

            const newFindings: Finding[] = eventData.findings.map((f) => ({
              id: crypto.randomUUID(),
              severity: f.severity.toUpperCase() as Finding["severity"],
              rule: f.rule_id,
              evidence: f.evidence,
              detail: f.title,
            }));

            if (stepIdx >= 0) {
              next.steps[stepIdx] = {
                ...next.steps[stepIdx],
                status: "complete",
                duration_ms: eventData.duration_ms,
                detail: eventData.detail,
                findings: newFindings,
              };
            } else {
              next.steps.push({
                id: crypto.randomUUID(),
                name: eventData.probe_id,
                duration_ms: eventData.duration_ms,
                status: "complete",
                detail: eventData.detail,
                findings: newFindings,
              });
            }

            next.findings.push(...newFindings);
            return next;
          });
        });

        eventSource.addEventListener("verdict", (e) => {
          const eventData: VerdictEvent = JSON.parse(e.data);
          setActiveScan((prev) => {
            if (!prev) return prev;
            return {
              ...prev,
              verdict: eventData.verdict.toUpperCase() as Verdict,
              action: eventData.verdict === "block" ? "blocked" : "passed",
              totalDuration_ms: eventData.duration_ms,
            };
          });
        });

        eventSource.addEventListener("complete", (e) => {
          const eventData: VerdictEvent = JSON.parse(e.data);
          setActiveScan((prev) => {
            if (!prev) return prev;
            return {
              ...prev,
              verdict: eventData.verdict.toUpperCase() as Verdict,
              action: eventData.verdict === "block" ? "blocked" : "passed",
              totalDuration_ms: eventData.duration_ms,
              complete: true,
            };
          });
          setIsScanning(false);
          closeEventSource();
        });

        eventSource.addEventListener("error", (e) => {
          let errorMessage = "Unknown error";
          try {
            if (e instanceof MessageEvent && e.data) {
              const eventData = JSON.parse(e.data);
              errorMessage = eventData.message || "Scan failed";
            }
          } catch {
            // Ignore parse errors
          }
          console.error("Scan error:", errorMessage);
          setActiveScan((prev) => {
            if (!prev) return prev;
            return {
              ...prev,
              complete: true,
            };
          });
          setIsScanning(false);
          closeEventSource();
        });

        eventSource.onerror = () => {
          if (eventSource.readyState === EventSource.CLOSED) {
            setIsScanning(false);
            closeEventSource();
          }
        };
      } catch (error) {
        console.error("Failed to start scan:", error);
        setActiveScan((prev) => {
          if (!prev) return prev;
          return { ...prev, complete: true };
        });
        setIsScanning(false);
      }
    },
    [closeEventSource]
  );

  return { scan, activeScan, isScanning };
}
