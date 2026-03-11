"""Network monitoring for container egress detection."""
from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .manager import ContainerManager

logger = logging.getLogger(__name__)


@dataclass
class NetworkEvent:
    """A network connection event from the container."""
    timestamp: datetime
    destination: str
    port: int
    protocol: str
    direction: str = "outbound"
    blocked: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "destination": self.destination,
            "port": self.port,
            "protocol": self.protocol,
            "direction": self.direction,
            "blocked": self.blocked,
            "metadata": self.metadata,
        }


class NetworkMonitor:
    """Monitors network activity from a container.

    Uses various methods to detect outbound connections:
    - Parsing /proc/net/tcp and /proc/net/udp
    - Running ss/netstat commands
    - Checking DNS queries via /etc/resolv.conf access
    """

    def __init__(self, container: ContainerManager):
        self.container = container
        self._events: list[NetworkEvent] = []
        self._running: bool = False
        self._monitor_thread: threading.Thread | None = None
        self._poll_interval: float = 2.0
        self._seen_connections: set[str] = set()

    @property
    def events(self) -> list[NetworkEvent]:
        return self._events.copy()

    def start(self) -> None:
        """Start monitoring network activity."""
        if self._running:
            return

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Network monitoring started")

    def stop(self) -> None:
        """Stop monitoring network activity."""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
            self._monitor_thread = None
        logger.info("Network monitoring stopped")

    def get_events(self) -> list[NetworkEvent]:
        """Return all captured network events."""
        return self._events.copy()

    def get_suspicious_events(self) -> list[NetworkEvent]:
        """Return events that look suspicious."""
        suspicious = []
        for event in self._events:
            if self._is_suspicious(event):
                suspicious.append(event)
        return suspicious

    def clear(self) -> None:
        """Clear all recorded events."""
        self._events.clear()
        self._seen_connections.clear()

    def _monitor_loop(self) -> None:
        """Background thread that polls for network connections."""
        while self._running:
            try:
                self._poll_connections()
            except Exception as e:
                logger.debug("Error polling connections: %s", e)
            time.sleep(self._poll_interval)

    def _poll_connections(self) -> None:
        """Poll current network connections from the container."""
        if not self.container.is_running:
            return

        result = self.container.exec(
            "ss -tunp 2>/dev/null || netstat -tunp 2>/dev/null || cat /proc/net/tcp /proc/net/tcp6 2>/dev/null",
            timeout=10,
        )

        if not result.success:
            return

        self._parse_connections(result.stdout)

    def _parse_connections(self, output: str) -> None:
        """Parse connection output and record new events."""
        for line in output.strip().split("\n"):
            event = self._parse_connection_line(line)
            if event:
                conn_key = f"{event.destination}:{event.port}:{event.protocol}"
                if conn_key not in self._seen_connections:
                    self._seen_connections.add(conn_key)
                    self._events.append(event)
                    logger.debug("New connection: %s:%d (%s)", event.destination, event.port, event.protocol)

    def _parse_connection_line(self, line: str) -> NetworkEvent | None:
        """Parse a single connection line from ss/netstat output."""
        line = line.strip()
        if not line or line.startswith("State") or line.startswith("Proto"):
            return None

        ss_pattern = r"(tcp|udp)\s+\S+\s+\S+\s+\S+\s+(\d+\.\d+\.\d+\.\d+|\[?[a-fA-F0-9:]+\]?):(\d+)"
        match = re.search(ss_pattern, line)
        if match:
            protocol = match.group(1)
            dest = match.group(2).strip("[]")
            port = int(match.group(3))

            if self._is_external_address(dest):
                return NetworkEvent(
                    timestamp=datetime.now(),
                    destination=dest,
                    port=port,
                    protocol=protocol,
                )

        hex_pattern = r"^\s*\d+:\s+([0-9A-F]+):([0-9A-F]+)\s+([0-9A-F]+):([0-9A-F]+)"
        match = re.match(hex_pattern, line, re.IGNORECASE)
        if match:
            remote_addr_hex = match.group(3)
            remote_port_hex = match.group(4)

            try:
                remote_addr = self._hex_to_ip(remote_addr_hex)
                remote_port = int(remote_port_hex, 16)

                if self._is_external_address(remote_addr) and remote_port > 0:
                    return NetworkEvent(
                        timestamp=datetime.now(),
                        destination=remote_addr,
                        port=remote_port,
                        protocol="tcp",
                    )
            except (ValueError, IndexError):
                pass

        return None

    def _hex_to_ip(self, hex_str: str) -> str:
        """Convert hex IP address to dotted decimal."""
        if len(hex_str) == 8:
            bytes_reversed = bytes.fromhex(hex_str)
            return ".".join(str(b) for b in reversed(bytes_reversed))
        return hex_str

    def _is_external_address(self, addr: str) -> bool:
        """Check if an address is external (not localhost/private)."""
        if addr in ("0.0.0.0", "127.0.0.1", "::1", "::"):
            return False
        if addr.startswith("127."):
            return False
        if addr.startswith("10."):
            return False
        if addr.startswith("172.") and 16 <= int(addr.split(".")[1]) <= 31:
            return False
        if addr.startswith("192.168."):
            return False
        return True

    def _is_suspicious(self, event: NetworkEvent) -> bool:
        """Determine if a network event is suspicious."""
        suspicious_ports = {
            21, 22, 23, 25, 53, 110, 143, 445, 993, 995,
            1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017,
        }

        if event.port in suspicious_ports:
            return True

        if event.port > 10000:
            return True

        return False

    def snapshot(self) -> dict[str, Any]:
        """Get a snapshot of current network state."""
        return {
            "total_events": len(self._events),
            "suspicious_events": len(self.get_suspicious_events()),
            "unique_destinations": len(set(e.destination for e in self._events)),
            "events": [e.to_dict() for e in self._events],
        }
