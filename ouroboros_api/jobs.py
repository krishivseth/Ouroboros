"""Job queue and state management for async operations."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from collections.abc import AsyncIterator

from .models import JobStatus, AuditEvent

logger = logging.getLogger(__name__)


@dataclass
class Job:
    """Represents an async job."""
    job_id: str
    status: JobStatus = JobStatus.PENDING
    result: Any = None
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    events: list[AuditEvent] = field(default_factory=list)
    _event_queue: asyncio.Queue | None = field(default=None, repr=False)

    def __post_init__(self):
        self._event_queue = asyncio.Queue()

    async def emit_event(self, event_type: str, data: dict[str, Any]) -> None:
        """Emit an event for this job."""
        event = AuditEvent(type=event_type, data=data)
        self.events.append(event)
        if self._event_queue:
            await self._event_queue.put(event)

    async def get_events(self) -> AsyncIterator[AuditEvent]:
        """Async iterator for job events."""
        if not self._event_queue:
            return
        
        while True:
            try:
                event = await asyncio.wait_for(self._event_queue.get(), timeout=30.0)
                yield event
                if event.type == "complete" or event.type == "error":
                    break
            except asyncio.TimeoutError:
                yield AuditEvent(type="heartbeat", data={"status": self.status.value})
                if self.status in (JobStatus.COMPLETED, JobStatus.FAILED):
                    break

    def complete(self, result: Any) -> None:
        """Mark job as completed."""
        self.status = JobStatus.COMPLETED
        self.result = result
        self.completed_at = datetime.utcnow()

    def fail(self, error: str) -> None:
        """Mark job as failed."""
        self.status = JobStatus.FAILED
        self.error = error
        self.completed_at = datetime.utcnow()


class JobStore:
    """In-memory job store."""

    def __init__(self, max_jobs: int = 100):
        self._jobs: dict[str, Job] = {}
        self._max_jobs = max_jobs

    def create(self, job_id: str) -> Job:
        """Create a new job."""
        if len(self._jobs) >= self._max_jobs:
            self._cleanup_old_jobs()
        
        job = Job(job_id=job_id)
        self._jobs[job_id] = job
        logger.info("Created job %s", job_id)
        return job

    def get(self, job_id: str) -> Job | None:
        """Get a job by ID."""
        return self._jobs.get(job_id)

    def _cleanup_old_jobs(self) -> None:
        """Remove oldest completed jobs."""
        completed = [
            (jid, job) for jid, job in self._jobs.items()
            if job.status in (JobStatus.COMPLETED, JobStatus.FAILED)
        ]
        completed.sort(key=lambda x: x[1].created_at)
        
        to_remove = len(self._jobs) - self._max_jobs // 2
        for jid, _ in completed[:to_remove]:
            del self._jobs[jid]
            logger.debug("Cleaned up job %s", jid)


scan_jobs = JobStore()
audit_jobs = JobStore()
runtime_scan_jobs = JobStore()
