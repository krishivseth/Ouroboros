"""Verdict cache with LRU eviction and TTL."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from mcp_scanner.models import RuntimeVerdict


@dataclass
class CacheEntry:
    """A cached verdict with timestamp."""
    verdict: RuntimeVerdict
    timestamp: float


class VerdictCache:
    """Thread-safe LRU cache for runtime verdicts.

    Cache key is computed from tool_name, input_params, and response_body.
    Entries expire after TTL seconds.
    """

    def __init__(
        self,
        max_size: int = 1024,
        ttl_seconds: float = 300.0,
    ):
        self._max_size = max_size
        self._ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()

    def compute_key(
        self,
        tool_name: str | None,
        input_params: dict[str, Any] | None,
        response_body: str | None,
    ) -> str:
        """Compute cache key from request/response data."""
        key_data = json.dumps({
            "tool": tool_name or "",
            "params": input_params or {},
            "response": response_body or "",
        }, sort_keys=True, default=str)
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, key: str) -> RuntimeVerdict | None:
        """Retrieve a cached verdict if it exists and hasn't expired."""
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None

            if time.time() - entry.timestamp > self._ttl_seconds:
                del self._cache[key]
                return None

            self._cache.move_to_end(key)
            return entry.verdict

    def put(self, key: str, verdict: RuntimeVerdict) -> None:
        """Store a verdict in the cache."""
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = CacheEntry(verdict=verdict, timestamp=time.time())
            else:
                if len(self._cache) >= self._max_size:
                    self._cache.popitem(last=False)
                self._cache[key] = CacheEntry(verdict=verdict, timestamp=time.time())

    def invalidate(self, key: str) -> None:
        """Remove a specific entry from the cache."""
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all entries from the cache."""
        with self._lock:
            self._cache.clear()

    def size(self) -> int:
        """Return current number of entries in the cache."""
        with self._lock:
            return len(self._cache)

    def cleanup_expired(self) -> int:
        """Remove all expired entries. Returns count of removed entries."""
        now = time.time()
        removed = 0
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if now - entry.timestamp > self._ttl_seconds
            ]
            for key in expired_keys:
                del self._cache[key]
                removed += 1
        return removed
