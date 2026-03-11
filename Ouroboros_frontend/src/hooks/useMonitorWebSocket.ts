import { useEffect, useRef, useCallback, useState } from "react";
import type { WsEvent, RuntimeVerdict } from "@/types/ouroboros";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_URL = API_URL.replace(/^http/, "ws");

interface UseMonitorWebSocketReturn {
  connected: boolean;
  proxyRunning: boolean;
}

export function useMonitorWebSocket(
  onEvent: (event: WsEvent) => void,
  enabled: boolean = true
): UseMonitorWebSocketReturn {
  const [connected, setConnected] = useState(false);
  const [proxyRunning, setProxyRunning] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      const ws = new WebSocket(`${WS_URL}/api/monitor/ws`);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log("Monitor WebSocket connected");
        setConnected(true);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          
          // Transform backend event format to frontend WsEvent format
          if (data.type === "call_start") {
            onEvent({
              type: "call_start",
              id: data.data.id,
              target: data.data.target,
              targetType: data.data.targetType,
              toolName: data.data.toolName,
              timestamp: data.data.timestamp,
            });
          } else if (data.type === "probe_result") {
            onEvent({
              type: "probe_result",
              id: data.data.id,
              probe: data.data.probe,
              duration_ms: data.data.duration_ms,
              findings: data.data.findings || [],
              detail: data.data.detail || [],
            });
          } else if (data.type === "verdict") {
            onEvent({
              type: "verdict",
              id: data.data.id,
              verdict: data.data.verdict as RuntimeVerdict,
            });
          } else if (data.type === "escalation_start") {
            onEvent({
              type: "escalation_start",
              id: data.data.id,
            });
          } else if (data.type === "escalation_chunk") {
            onEvent({
              type: "escalation_chunk",
              id: data.data.id,
              text: data.data.text,
            });
          } else if (data.type === "escalation_end") {
            onEvent({
              type: "escalation_end",
              id: data.data.id,
              duration_ms: data.data.duration_ms,
            });
          }
          // Ignore heartbeat events
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e);
        }
      };

      ws.onclose = () => {
        console.log("Monitor WebSocket disconnected");
        setConnected(false);
        wsRef.current = null;

        // Reconnect after delay
        if (enabled) {
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, 3000);
        }
      };

      ws.onerror = (error) => {
        console.error("Monitor WebSocket error:", error);
      };
    } catch (e) {
      console.error("Failed to create WebSocket:", e);
      setConnected(false);
    }
  }, [enabled, onEvent]);

  // Check proxy status periodically
  useEffect(() => {
    if (!enabled) return;

    const checkStatus = async () => {
      try {
        const response = await fetch(`${API_URL}/api/monitor/status`);
        if (response.ok) {
          const data = await response.json();
          setProxyRunning(data.proxy_running);
        }
      } catch {
        // Ignore errors
      }
    };

    checkStatus();
    const interval = setInterval(checkStatus, 10000);

    return () => clearInterval(interval);
  }, [enabled]);

  useEffect(() => {
    if (enabled) {
      connect();
    }

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setConnected(false);
    };
  }, [enabled, connect]);

  return { connected, proxyRunning };
}
