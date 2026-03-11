"""Test script to emit mock MCP events to the Monitor tab."""
import asyncio
import uuid
from datetime import datetime
import aiohttp

API_URL = "http://localhost:8000"


async def emit_event(session: aiohttp.ClientSession, event_type: str, data: dict):
    """Emit an event to the monitor API."""
    async with session.post(
        f"{API_URL}/api/monitor/emit",
        json={"type": event_type, "data": data},
    ) as resp:
        if resp.status != 200:
            print(f"Failed to emit {event_type}: {await resp.text()}")
        else:
            print(f"Emitted: {event_type}")


async def simulate_mcp_call(session: aiohttp.ClientSession, tool_name: str, target: str):
    """Simulate a complete MCP tool call with probes and verdict."""
    call_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    
    # 1. Emit call_start
    await emit_event(session, "call_start", {
        "id": call_id,
        "target": target,
        "targetType": "mcp",
        "toolName": tool_name,
        "timestamp": timestamp,
    })
    await asyncio.sleep(0.1)
    
    # 2. Emit probe results
    probes = [
        ("CLASSIFY", 15, ["Target type: MCP tool call", f"Tool: {tool_name}", "Server: mcp-server.local"]),
        ("PROBE: injection", 25, ["Scanned response body (2.3KB)", "✓ No coercive patterns", "✓ No markdown image exfiltration"]),
        ("PROBE: headers", 8, ["✓ Valid response headers", "✓ No server version leak"]),
        ("PROBE: ssl", 45, ["✓ Valid certificate chain", "✓ TLS 1.3", "✓ Hostname matches"]),
    ]
    
    for probe_name, duration, detail in probes:
        await emit_event(session, "probe_result", {
            "id": call_id,
            "probe": probe_name,
            "duration_ms": duration,
            "findings": [],
            "detail": detail,
        })
        await asyncio.sleep(0.15)
    
    # 3. Emit verdict
    await emit_event(session, "verdict", {
        "id": call_id,
        "verdict": {
            "id": call_id,
            "target": target,
            "targetType": "mcp",
            "toolName": tool_name,
            "timestamp": timestamp,
            "verdict": "SAFE",
            "action": "passed",
            "totalDuration_ms": 93,
            "steps": [],
            "findings": [],
        },
    })
    
    print(f"✓ Completed MCP call simulation for {tool_name}")


async def simulate_suspicious_call(session: aiohttp.ClientSession):
    """Simulate a suspicious MCP call that gets flagged."""
    call_id = str(uuid.uuid4())
    timestamp = datetime.utcnow().isoformat()
    tool_name = "fetch_url"
    target = "https://suspicious-site.example.com/api"
    
    await emit_event(session, "call_start", {
        "id": call_id,
        "target": target,
        "targetType": "mcp",
        "toolName": tool_name,
        "timestamp": timestamp,
    })
    await asyncio.sleep(0.1)
    
    # Probes with findings
    await emit_event(session, "probe_result", {
        "id": call_id,
        "probe": "CLASSIFY",
        "duration_ms": 12,
        "findings": [],
        "detail": ["Target type: MCP tool call", f"Tool: {tool_name}", "Server: external-mcp.local"],
    })
    await asyncio.sleep(0.15)
    
    await emit_event(session, "probe_result", {
        "id": call_id,
        "probe": "PROBE: injection",
        "duration_ms": 35,
        "findings": [{
            "id": str(uuid.uuid4()),
            "severity": "HIGH",
            "rule": "PROMPT_INJECTION",
            "evidence": 'Detected coercive pattern: "ignore previous instructions"',
        }],
        "detail": [
            "Scanned response body (4.1KB)",
            "✗ Coercive pattern detected",
            "✗ Potential prompt injection",
        ],
    })
    await asyncio.sleep(0.15)
    
    await emit_event(session, "probe_result", {
        "id": call_id,
        "probe": "PROBE: headers",
        "duration_ms": 5,
        "findings": [{
            "id": str(uuid.uuid4()),
            "severity": "LOW",
            "rule": "HEADER_MISCONFIGURATION",
            "evidence": "Missing Strict-Transport-Security header",
        }],
        "detail": ["✗ Missing HSTS header", "⚠ Weak CSP policy"],
    })
    await asyncio.sleep(0.15)
    
    await emit_event(session, "probe_result", {
        "id": call_id,
        "probe": "PROBE: ssl",
        "duration_ms": 40,
        "findings": [],
        "detail": ["✓ Valid certificate chain", "⚠ TLS 1.2 (upgrade recommended)"],
    })
    await asyncio.sleep(0.1)
    
    # Escalation
    await emit_event(session, "escalation_start", {"id": call_id})
    await asyncio.sleep(0.2)
    
    escalation_text = "The response contains a coercive instruction pattern attempting to override the agent's behavior. The phrase 'ignore previous instructions' is a known prompt injection technique. Recommending CAUTION verdict with user notification."
    
    # Stream escalation text in chunks
    for i in range(0, len(escalation_text), 5):
        await emit_event(session, "escalation_chunk", {
            "id": call_id,
            "text": escalation_text[i:i+5],
        })
        await asyncio.sleep(0.03)
    
    await emit_event(session, "escalation_end", {
        "id": call_id,
        "duration_ms": 1500,
    })
    await asyncio.sleep(0.1)
    
    # Verdict: CAUTION
    await emit_event(session, "verdict", {
        "id": call_id,
        "verdict": {
            "id": call_id,
            "target": target,
            "targetType": "mcp",
            "toolName": tool_name,
            "timestamp": timestamp,
            "verdict": "CAUTION",
            "action": "warned",
            "policyRule": "warn_on_injection",
            "totalDuration_ms": 1692,
            "steps": [],
            "findings": [
                {
                    "id": str(uuid.uuid4()),
                    "severity": "HIGH",
                    "rule": "PROMPT_INJECTION",
                    "evidence": 'Detected coercive pattern: "ignore previous instructions"',
                },
                {
                    "id": str(uuid.uuid4()),
                    "severity": "LOW",
                    "rule": "HEADER_MISCONFIGURATION",
                    "evidence": "Missing Strict-Transport-Security header",
                },
            ],
        },
    })
    
    print(f"✓ Completed suspicious MCP call simulation (CAUTION)")


async def main():
    print("=" * 60)
    print("Ouroboros Monitor Tab Test")
    print("=" * 60)
    print("\nEmitting test events to the Monitor tab...\n")
    
    async with aiohttp.ClientSession() as session:
        # Check API is running
        try:
            async with session.get(f"{API_URL}/api/monitor/status") as resp:
                if resp.status != 200:
                    print("ERROR: API not responding. Make sure the backend is running.")
                    return
                status = await resp.json()
                print(f"API Status: {status['connected_clients']} WebSocket clients connected\n")
        except Exception as e:
            print(f"ERROR: Cannot connect to API: {e}")
            return
        
        # Simulate several MCP calls
        print("Simulating MCP tool calls...\n")
        
        await simulate_mcp_call(session, "web_search", "search for NYC restaurants")
        await asyncio.sleep(0.5)
        
        await simulate_mcp_call(session, "read_url", "https://api.yelp.com/v3/businesses")
        await asyncio.sleep(0.5)
        
        await simulate_suspicious_call(session)
        await asyncio.sleep(0.5)
        
        await simulate_mcp_call(session, "google_maps_search", "Times Square, New York")
        
        print("\n" + "=" * 60)
        print("Test complete! Check the Monitor tab in the frontend.")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
