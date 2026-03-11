"""Pydantic models for API requests and responses."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class JobStatus(str, Enum):
    """Status of an async job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(str, Enum):
    """Security verdict."""
    SAFE = "safe"
    CAUTION = "caution"
    BLOCK = "block"


class Severity(str, Enum):
    """Finding severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanRequest(BaseModel):
    """Request to start a static scan."""
    target_path: str = Field(..., description="Path to the MCP server code")
    severity_filter: Severity | None = Field(None, description="Minimum severity to report")


class ScanResponse(BaseModel):
    """Response from starting a scan."""
    job_id: str
    status: JobStatus
    message: str


class Finding(BaseModel):
    """A security finding."""
    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    target: str | None = None
    evidence: str | None = None
    snippet: str | None = None


class ScanResult(BaseModel):
    """Result of a static scan."""
    job_id: str
    status: JobStatus
    target_path: str
    findings: list[Finding] = []
    files_scanned: int = 0
    duration_seconds: float = 0.0
    error: str | None = None


class AuditRequest(BaseModel):
    """Request to start a sandbox audit."""
    target_path: str = Field(..., description="Path to the MCP server code")
    start_command: str | None = Field(None, description="Command to start the server")
    base_image: str = Field("python:3.12-slim", description="Docker base image")
    max_iterations: int = Field(30, description="Maximum agent iterations")
    skip_static: bool = Field(False, description="Skip static analysis")


class AuditResponse(BaseModel):
    """Response from starting an audit."""
    job_id: str
    status: JobStatus
    message: str


class NetworkEvent(BaseModel):
    """A network connection event."""
    timestamp: datetime
    destination: str
    port: int
    protocol: str


class ToolProbe(BaseModel):
    """A tool that was probed."""
    tool_name: str
    description: str | None = None
    arguments: dict[str, Any] | None = None
    result_summary: str | None = None


class AuditResult(BaseModel):
    """Result of a sandbox audit."""
    job_id: str
    status: JobStatus
    target_path: str
    verdict: Verdict | None = None
    static_findings: list[Finding] = []
    dynamic_findings: list[Finding] = []
    network_events: list[NetworkEvent] = []
    tools_probed: list[ToolProbe] = []
    duration_seconds: float = 0.0
    narrative: str = ""
    error: str | None = None


class AuditEvent(BaseModel):
    """An event emitted during audit progress."""
    type: str
    data: dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    docker_available: bool
    bedrock_configured: bool


# Runtime scan models
class RuntimeScanRequest(BaseModel):
    """Request to start a runtime URL scan."""
    target_url: str = Field(..., description="URL to scan")
    include_safebrowsing: bool = Field(True, description="Include Google Safe Browsing check if API key available")
    include_virustotal: bool = Field(True, description="Include VirusTotal check if API key available")


class RuntimeScanResponse(BaseModel):
    """Response from starting a runtime scan."""
    job_id: str
    status: JobStatus
    message: str
    available_probes: list[str] = []


class ProbeResultModel(BaseModel):
    """Result from a single probe execution."""
    probe_id: str
    duration_ms: float
    findings_count: int
    detail: list[str] = []


class RuntimeScanResult(BaseModel):
    """Result of a runtime URL scan."""
    job_id: str
    status: JobStatus
    target_url: str
    verdict: Verdict | None = None
    findings: list[Finding] = []
    probe_results: list[ProbeResultModel] = []
    duration_ms: float = 0.0
    error: str | None = None
