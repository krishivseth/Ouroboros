"""Real Bedrock agent test with Monitor tab integration."""
import asyncio
import json
import uuid
from datetime import datetime, timezone
import aiohttp
import boto3

API_URL = "http://localhost:8000"

# Bedrock client
bedrock = boto3.client(
    "bedrock-runtime",
    region_name="us-east-1",
)


async def emit_event(session: aiohttp.ClientSession, event_type: str, data: dict):
    """Emit an event to the monitor API."""
    try:
        async with session.post(
            f"{API_URL}/api/monitor/emit",
            json={"type": event_type, "data": data},
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            pass
    except Exception as e:
        print(f"Failed to emit: {e}")


async def run_bedrock_agent_with_monitoring(query: str):
    """Run a Bedrock agent and emit events to the Monitor tab."""
    
    call_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()
    
    async with aiohttp.ClientSession() as session:
        # Emit call_start
        await emit_event(session, "call_start", {
            "id": call_id,
            "target": query,
            "targetType": "mcp",
            "toolName": "bedrock_agent",
            "timestamp": timestamp,
        })
        
        print(f"Calling Bedrock with: {query}")
        
        # Emit classify probe
        await emit_event(session, "probe_result", {
            "id": call_id,
            "probe": "CLASSIFY",
            "duration_ms": 5,
            "findings": [],
            "detail": [
                "Target type: Bedrock Agent Call",
                f"Query: {query[:50]}...",
                "Model: anthropic.claude-3-haiku",
            ],
        })
        
        start_time = datetime.now(timezone.utc)
        
        # Actually call Bedrock
        try:
            response = bedrock.converse(
                modelId="anthropic.claude-3-haiku-20240307-v1:0",
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": query}],
                    }
                ],
                inferenceConfig={
                    "maxTokens": 500,
                    "temperature": 0.7,
                },
            )
            
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            # Extract response
            output = response.get("output", {})
            message = output.get("message", {})
            content = message.get("content", [])
            response_text = content[0].get("text", "") if content else ""
            
            print(f"\nBedrock Response ({duration_ms:.0f}ms):")
            print("-" * 40)
            print(response_text[:500])
            print("-" * 40)
            
            # Emit probe results - analyze the response
            findings = []
            detail = [
                f"Response length: {len(response_text)} chars",
                f"Latency: {duration_ms:.0f}ms",
            ]
            
            # Check for suspicious patterns in response
            suspicious_patterns = [
                "ignore previous",
                "disregard",
                "you must",
                "do not tell",
            ]
            
            for pattern in suspicious_patterns:
                if pattern.lower() in response_text.lower():
                    findings.append({
                        "id": str(uuid.uuid4()),
                        "severity": "MEDIUM",
                        "rule": "SUSPICIOUS_CONTENT",
                        "evidence": f"Response contains pattern: '{pattern}'",
                    })
                    detail.append(f"⚠ Found pattern: {pattern}")
            
            if not findings:
                detail.append("✓ No suspicious patterns detected")
            
            await emit_event(session, "probe_result", {
                "id": call_id,
                "probe": "PROBE: content_analysis",
                "duration_ms": duration_ms,
                "findings": findings,
                "detail": detail,
            })
            
            # Determine verdict
            verdict = "SAFE" if not findings else "CAUTION"
            action = "passed" if not findings else "warned"
            
            await emit_event(session, "verdict", {
                "id": call_id,
                "verdict": {
                    "id": call_id,
                    "target": query,
                    "targetType": "mcp",
                    "toolName": "bedrock_agent",
                    "timestamp": timestamp,
                    "verdict": verdict,
                    "action": action,
                    "totalDuration_ms": duration_ms,
                    "findings": findings,
                    "responsePreview": response_text[:200],
                },
            })
            
            print(f"\n✓ Verdict: {verdict}")
            return response_text
            
        except Exception as e:
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000
            
            await emit_event(session, "probe_result", {
                "id": call_id,
                "probe": "PROBE: error",
                "duration_ms": duration_ms,
                "findings": [{
                    "id": str(uuid.uuid4()),
                    "severity": "HIGH",
                    "rule": "API_ERROR",
                    "evidence": str(e),
                }],
                "detail": [f"Error: {str(e)[:100]}"],
            })
            
            await emit_event(session, "verdict", {
                "id": call_id,
                "verdict": {
                    "id": call_id,
                    "target": query,
                    "targetType": "mcp",
                    "toolName": "bedrock_agent",
                    "timestamp": timestamp,
                    "verdict": "BLOCK",
                    "action": "blocked",
                    "totalDuration_ms": duration_ms,
                    "findings": [{
                        "id": str(uuid.uuid4()),
                        "severity": "HIGH",
                        "rule": "API_ERROR",
                        "evidence": str(e),
                    }],
                },
            })
            
            print(f"\n✗ Error: {e}")
            raise


async def main():
    print("=" * 60)
    print("Real Bedrock Agent Test with Monitor Integration")
    print("=" * 60)
    
    # Check API status
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"{API_URL}/api/monitor/status") as resp:
                status = await resp.json()
                print(f"\nMonitor: {status['connected_clients']} clients connected")
        except:
            print("\nWARNING: Monitor API not reachable")
    
    print("\n" + "-" * 60)
    
    # Run real queries
    queries = [
        "What are the top 3 restaurants in Times Square NYC? Just list names briefly.",
        "Search for the best pizza places in Manhattan.",
    ]
    
    for query in queries:
        print(f"\n>>> Query: {query}\n")
        try:
            await run_bedrock_agent_with_monitoring(query)
        except Exception as e:
            print(f"Failed: {e}")
        
        await asyncio.sleep(1)
    
    print("\n" + "=" * 60)
    print("Check the Monitor tab for real Bedrock agent traffic!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
