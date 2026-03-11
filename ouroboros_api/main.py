"""FastAPI application for Ouroboros Security API."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse

from . import __version__
from .models import (
    ScanRequest, ScanResponse, ScanResult,
    AuditRequest, AuditResponse, AuditResult,
    HealthResponse, JobStatus, Verdict, Severity,
    Finding, NetworkEvent, ToolProbe,
    RuntimeScanRequest, RuntimeScanResponse, RuntimeScanResult, ProbeResultModel,
)
from .jobs import scan_jobs, audit_jobs, runtime_scan_jobs, Job
from .streaming import EventEmitter
from .monitor import monitor_bus, MonitorEvent

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Ouroboros Security API",
    description="API for MCP server security scanning and sandbox auditing",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _check_docker() -> bool:
    """Check if Docker is available."""
    try:
        import docker
        client = docker.from_env()
        client.ping()
        return True
    except Exception:
        return False


def _check_bedrock() -> bool:
    """Check if Bedrock credentials are configured."""
    return bool(
        os.environ.get("AWS_ACCESS_KEY_ID") or
        os.environ.get("AWS_PROFILE") or
        os.environ.get("ANTHROPIC_API_KEY")
    )


def _is_github_url(path: str) -> bool:
    """Check if the path is a GitHub URL."""
    if not path:
        return False
    try:
        parsed = urlparse(path)
        return parsed.scheme in ("http", "https") and "github.com" in parsed.netloc
    except Exception:
        return False


def _clone_repo(url: str, target_dir: str) -> str:
    """Clone a GitHub repository to a target directory.
    
    Returns the path to the cloned repository.
    """
    logger.info("Cloning repository: %s", url)
    
    # Parse and clean the URL - remove query params and fragments
    parsed = urlparse(url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    # Normalize the URL (remove trailing slashes, .git suffix handling)
    clean_url = clean_url.rstrip("/")
    if not clean_url.endswith(".git"):
        clean_url = clean_url + ".git"
    
    logger.info("Cleaned URL: %s", clean_url)
    
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", clean_url, target_dir],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Git clone failed: {result.stderr}")
        
        logger.info("Repository cloned to: %s", target_dir)
        return target_dir
        
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git clone timed out after 120 seconds")
    except FileNotFoundError:
        raise RuntimeError("Git is not installed or not in PATH")


@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Check API health and dependencies."""
    return HealthResponse(
        status="healthy",
        version=__version__,
        docker_available=_check_docker(),
        bedrock_configured=_check_bedrock(),
    )


@app.post("/api/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a static security scan."""
    job_id = str(uuid.uuid4())
    job = scan_jobs.create(job_id)
    job.status = JobStatus.RUNNING
    
    background_tasks.add_task(_run_scan_job, job, request)
    
    return ScanResponse(
        job_id=job_id,
        status=JobStatus.RUNNING,
        message=f"Scan started for {request.target_path}",
    )


async def _run_scan_job(job: Job, request: ScanRequest) -> None:
    """Run the static scan in background."""
    try:
        from mcp_scanner.engine import scan
        
        result = scan(request.target_path)
        
        findings = []
        for f in result.findings:
            if request.severity_filter:
                if f.severity.rank < Severity(request.severity_filter).rank:
                    continue
            findings.append(Finding(
                rule_id=f.rule_id.value,
                severity=Severity(f.severity.value),
                title=f.title,
                description=f.description,
                file_path=f.file_path,
                line_number=f.line_number,
                snippet=f.snippet,
            ))
        
        job.complete(ScanResult(
            job_id=job.job_id,
            status=JobStatus.COMPLETED,
            target_path=request.target_path,
            findings=findings,
            files_scanned=result.files_scanned,
            duration_seconds=result.duration_seconds,
        ))
        
    except Exception as e:
        logger.exception("Scan failed")
        job.fail(str(e))


@app.get("/api/scan/{job_id}", response_model=ScanResult)
async def get_scan_result(job_id: str):
    """Get the result of a scan job."""
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status == JobStatus.FAILED:
        return ScanResult(
            job_id=job_id,
            status=JobStatus.FAILED,
            target_path="",
            error=job.error,
        )
    
    if job.status == JobStatus.RUNNING:
        return ScanResult(
            job_id=job_id,
            status=JobStatus.RUNNING,
            target_path="",
        )
    
    return job.result


@app.post("/api/sandbox/audit", response_model=AuditResponse)
async def start_audit(request: AuditRequest, background_tasks: BackgroundTasks):
    """Start a sandbox security audit."""
    if not _check_docker():
        raise HTTPException(status_code=503, detail="Docker is not available")
    
    job_id = str(uuid.uuid4())
    job = audit_jobs.create(job_id)
    job.status = JobStatus.RUNNING
    
    background_tasks.add_task(_run_audit_job, job, request)
    
    return AuditResponse(
        job_id=job_id,
        status=JobStatus.RUNNING,
        message=f"Audit started for {request.target_path}",
    )


async def _run_audit_job(job: Job, request: AuditRequest) -> None:
    """Run the sandbox audit in background with event streaming."""
    emitter = EventEmitter(job)
    temp_dir = None
    
    try:
        await emitter.phase("initializing", "running")
        
        # Handle GitHub URLs by cloning the repository
        target_path = request.target_path
        if _is_github_url(target_path):
            temp_dir = tempfile.mkdtemp(prefix="ouroboros_audit_")
            await emitter.agent_thought(f"Cloning repository: {target_path}")
            try:
                target_path = _clone_repo(target_path, temp_dir)
            except RuntimeError as e:
                raise RuntimeError(f"Failed to clone repository: {e}")
        else:
            # Validate local path exists
            if not Path(target_path).exists():
                raise RuntimeError(f"Repository path not found: {target_path}")
        
        from ouroboros_sandbox.agent.auditor import audit
        
        await emitter.phase("static_scan", "running")
        
        report = await audit(
            target_path=target_path,  # Use the resolved/cloned path
            start_command=request.start_command,
            base_image=request.base_image,
            max_iterations=request.max_iterations,
            run_static_scan=not request.skip_static,
        )
        
        for f in report.static_findings:
            await emitter.finding(
                severity=f.severity.value,
                title=f.title,
                rule_id=f.rule_id.value,
                target=f.file_path,
                description=f.description,
            )
        
        for f in report.dynamic_findings:
            await emitter.finding(
                severity=f.severity.value,
                title=f.title,
                rule_id=f.rule_id.value,
                target=f.target,
                description=f.description,
            )
        
        static_findings = [
            Finding(
                rule_id=f.rule_id.value,
                severity=Severity(f.severity.value),
                title=f.title,
                description=f.description,
                file_path=f.file_path,
                line_number=f.line_number,
                snippet=f.snippet if hasattr(f, 'snippet') else None,
            )
            for f in report.static_findings
        ]
        
        dynamic_findings = [
            Finding(
                rule_id=f.rule_id.value,
                severity=Severity(f.severity.value),
                title=f.title,
                description=f.description,
                target=f.target,
                evidence=f.evidence,
            )
            for f in report.dynamic_findings
        ]
        
        network_events = [
            NetworkEvent(
                timestamp=e.timestamp,
                destination=e.destination,
                port=e.port,
                protocol=e.protocol,
            )
            for e in report.network_events
        ]
        
        tools_probed = [
            ToolProbe(
                tool_name=t.get("tool_name", "unknown"),
                description=t.get("description"),
                arguments=t.get("arguments"),
                result_summary=t.get("result_summary"),
            )
            for t in report.tools_probed
        ]
        
        result = AuditResult(
            job_id=job.job_id,
            status=JobStatus.COMPLETED,
            target_path=request.target_path,
            verdict=Verdict(report.overall_verdict.value),
            static_findings=static_findings,
            dynamic_findings=dynamic_findings,
            network_events=network_events,
            tools_probed=tools_probed,
            duration_seconds=report.duration_seconds,
            narrative=report.narrative,
        )
        
        await emitter.complete(
            verdict=report.overall_verdict.value,
            findings_count=len(static_findings) + len(dynamic_findings),
            duration_seconds=report.duration_seconds,
        )
        
        job.complete(result)
        
    except Exception as e:
        logger.exception("Audit failed")
        await emitter.error(str(e))
        job.fail(str(e))
    finally:
        # Clean up temporary directory if we cloned a repo
        if temp_dir and Path(temp_dir).exists():
            try:
                shutil.rmtree(temp_dir)
                logger.info("Cleaned up temp directory: %s", temp_dir)
            except Exception as cleanup_error:
                logger.warning("Failed to clean up temp directory: %s", cleanup_error)


@app.get("/api/sandbox/audit/{job_id}", response_model=AuditResult)
async def get_audit_result(job_id: str):
    """Get the result of an audit job."""
    job = audit_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status == JobStatus.FAILED:
        return AuditResult(
            job_id=job_id,
            status=JobStatus.FAILED,
            target_path="",
            error=job.error,
        )
    
    if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
        return AuditResult(
            job_id=job_id,
            status=job.status,
            target_path="",
        )
    
    return job.result


@app.get("/api/sandbox/audit/{job_id}/stream")
async def stream_audit(job_id: str):
    """Stream audit progress via SSE."""
    job = audit_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    async def event_generator():
        async for event in job.get_events():
            yield {
                "event": event.type,
                "data": json.dumps(event.data, default=str),
            }
    
    return EventSourceResponse(event_generator())


@app.get("/api/sandbox/audit/{job_id}/events")
async def get_audit_events(job_id: str):
    """Get all events for an audit job (non-streaming)."""
    job = audit_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return {
        "job_id": job_id,
        "status": job.status.value,
        "events": [
            {"type": e.type, "data": e.data, "timestamp": e.timestamp.isoformat()}
            for e in job.events
        ],
    }


# Runtime URL Scan Endpoints

@app.post("/api/runtime/scan", response_model=RuntimeScanResponse)
async def start_runtime_scan(request: RuntimeScanRequest, background_tasks: BackgroundTasks):
    """Start a runtime URL security scan."""
    from ouroboros_runtime.core.probes import get_available_probes, get_probe_availability
    
    job_id = str(uuid.uuid4())
    job = runtime_scan_jobs.create(job_id)
    job.status = JobStatus.RUNNING
    
    available_probes = get_available_probes(
        include_safebrowsing=request.include_safebrowsing,
        include_virustotal=request.include_virustotal,
    )
    probe_names = [p.probe_id for p in [cls() for cls in available_probes]]
    
    background_tasks.add_task(_run_runtime_scan_job, job, request)
    
    return RuntimeScanResponse(
        job_id=job_id,
        status=JobStatus.RUNNING,
        message=f"Scan started for {request.target_url}",
        available_probes=probe_names,
    )


async def _run_runtime_scan_job(job: Job, request: RuntimeScanRequest) -> None:
    """Run the runtime URL scan in background with event streaming."""
    import time
    from ouroboros_runtime.core.probes import get_available_probes
    from ouroboros_runtime.core.probes.base import ProbeInput
    from ouroboros_runtime.core.verdict import compute_verdict
    
    start_time = time.perf_counter()
    all_findings: list[Finding] = []
    probe_results: list[ProbeResultModel] = []
    reasoning: list[str] = []
    
    try:
        await job.emit_event("scan_start", {
            "target_url": request.target_url,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        probe_classes = get_available_probes(
            include_safebrowsing=request.include_safebrowsing,
            include_virustotal=request.include_virustotal,
        )
        
        probe_input = ProbeInput(url=request.target_url)
        
        for probe_cls in probe_classes:
            probe = probe_cls()
            probe_start = time.perf_counter()
            
            await job.emit_event("probe_start", {
                "probe_id": probe.probe_id,
            })
            
            try:
                findings = await asyncio.to_thread(probe.run, probe_input)
                probe_duration = (time.perf_counter() - probe_start) * 1000
                
                detail = []
                if findings:
                    detail.append(f"Found {len(findings)} issue(s)")
                    for f in findings:
                        all_findings.append(Finding(
                            rule_id=f.rule_id.value,
                            severity=Severity(f.severity.value),
                            title=f.title,
                            description=f.description,
                            target=f.target,
                            evidence=f.evidence,
                        ))
                        detail.append(f"  - {f.title}")
                else:
                    detail.append("No issues detected")
                
                probe_result = ProbeResultModel(
                    probe_id=probe.probe_id,
                    duration_ms=probe_duration,
                    findings_count=len(findings),
                    detail=detail,
                )
                probe_results.append(probe_result)
                
                await job.emit_event("probe_result", {
                    "probe_id": probe.probe_id,
                    "duration_ms": probe_duration,
                    "findings_count": len(findings),
                    "detail": detail,
                    "findings": [
                        {
                            "rule_id": f.rule_id.value,
                            "severity": f.severity.value,
                            "title": f.title,
                            "evidence": f.evidence,
                        }
                        for f in findings
                    ],
                })
                
                reasoning.append(f"{probe.probe_id}: {len(findings)} finding(s) in {probe_duration:.1f}ms")
                
            except Exception as e:
                logger.exception("Probe %s failed: %s", probe.probe_id, e)
                probe_duration = (time.perf_counter() - probe_start) * 1000
                probe_results.append(ProbeResultModel(
                    probe_id=probe.probe_id,
                    duration_ms=probe_duration,
                    findings_count=0,
                    detail=[f"Error: {str(e)}"],
                ))
                await job.emit_event("probe_error", {
                    "probe_id": probe.probe_id,
                    "error": str(e),
                })
                reasoning.append(f"{probe.probe_id}: ERROR - {e}")
        
        total_duration = (time.perf_counter() - start_time) * 1000
        
        from mcp_scanner.models import RuntimeFinding as MCPRuntimeFinding
        from mcp_scanner.models import Severity as MCPSeverity
        from mcp_scanner.models import RuleID as MCPRuleID
        
        mcp_findings = [
            MCPRuntimeFinding(
                rule_id=MCPRuleID(f.rule_id),
                severity=MCPSeverity(f.severity.value),
                title=f.title,
                description=f.description,
                target=f.target or request.target_url,
                evidence=f.evidence or "",
            )
            for f in all_findings
        ]
        
        verdict_result = compute_verdict(
            findings=mcp_findings,
            target=request.target_url,
            probe_duration_ms=total_duration,
            reasoning_chain=reasoning,
        )
        
        final_verdict = Verdict(verdict_result.verdict.value)
        
        result = RuntimeScanResult(
            job_id=job.job_id,
            status=JobStatus.COMPLETED,
            target_url=request.target_url,
            verdict=final_verdict,
            findings=all_findings,
            probe_results=probe_results,
            duration_ms=total_duration,
        )
        
        await job.emit_event("verdict", {
            "verdict": final_verdict.value,
            "findings_count": len(all_findings),
            "duration_ms": total_duration,
        })
        
        await job.emit_event("complete", {
            "verdict": final_verdict.value,
            "findings_count": len(all_findings),
            "duration_ms": total_duration,
        })
        
        job.complete(result)
        
    except Exception as e:
        logger.exception("Runtime scan failed")
        await job.emit_event("error", {"message": str(e)})
        job.fail(str(e))


@app.get("/api/runtime/scan/{job_id}", response_model=RuntimeScanResult)
async def get_runtime_scan_result(job_id: str):
    """Get the result of a runtime scan job."""
    job = runtime_scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job.status == JobStatus.FAILED:
        return RuntimeScanResult(
            job_id=job_id,
            status=JobStatus.FAILED,
            target_url="",
            error=job.error,
        )
    
    if job.status in (JobStatus.PENDING, JobStatus.RUNNING):
        return RuntimeScanResult(
            job_id=job_id,
            status=job.status,
            target_url="",
        )
    
    return job.result


@app.get("/api/runtime/scan/{job_id}/stream")
async def stream_runtime_scan(job_id: str):
    """Stream runtime scan progress via SSE."""
    job = runtime_scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    async def event_generator():
        async for event in job.get_events():
            yield {
                "event": event.type,
                "data": json.dumps(event.data, default=str),
            }
    
    return EventSourceResponse(event_generator())


@app.get("/api/runtime/probes")
async def get_available_probes_info():
    """Get information about available probes."""
    from ouroboros_runtime.core.probes import get_probe_availability, CORE_PROBES
    
    availability = get_probe_availability()
    
    return {
        "core_probes": [p.probe_id for p in [cls() for cls in CORE_PROBES]],
        "optional_probes": {
            "safebrowsing": {
                "available": availability["safebrowsing"],
                "env_var": "GOOGLE_SAFE_BROWSING_API_KEY",
            },
            "virustotal": {
                "available": availability["virustotal"],
                "env_var": "VIRUSTOTAL_API_KEY",
            },
        },
    }


# Monitor WebSocket endpoint for real-time MCP traffic

@app.websocket("/api/monitor/ws")
async def monitor_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time MCP traffic monitoring."""
    await websocket.accept()
    logger.info("Monitor WebSocket client connected")
    
    try:
        # Send recent history first
        for event in monitor_bus.get_history():
            await websocket.send_json({
                "type": event.type,
                "data": event.data,
                "timestamp": event.timestamp.isoformat(),
            })
        
        # Stream new events
        async for event in monitor_bus.subscribe():
            await websocket.send_json({
                "type": event.type,
                "data": event.data,
                "timestamp": event.timestamp.isoformat(),
            })
    except WebSocketDisconnect:
        logger.info("Monitor WebSocket client disconnected")
    except Exception as e:
        logger.exception("Monitor WebSocket error: %s", e)


@app.get("/api/monitor/status")
async def get_monitor_status():
    """Get monitor status including connected clients."""
    return {
        "connected_clients": monitor_bus.subscriber_count,
        "history_size": len(monitor_bus.get_history()),
        "proxy_running": monitor_bus.subscriber_count > 0,
    }


@app.post("/api/monitor/emit")
async def emit_monitor_event(event: dict):
    """Receive events from the proxy and broadcast to WebSocket clients."""
    event_type = event.get("type", "unknown")
    data = event.get("data", {})
    
    await monitor_bus.publish(MonitorEvent(type=event_type, data=data))
    
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
