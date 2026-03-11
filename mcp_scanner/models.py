from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleID(str, Enum):
    # Static scanner rules
    PROMPT_INJECTION = "prompt-injection"
    TOOL_POISONING = "tool-poisoning"
    EXCESSIVE_PERMISSIONS = "excessive-permissions"
    RUG_PULL = "rug-pull"
    TOOL_SHADOWING = "tool-shadowing"
    INDIRECT_PROMPT_INJECTION = "indirect-prompt-injection"
    TOKEN_LEAKAGE = "token-leakage"
    CODE_EXECUTION = "code-execution"
    COMMAND_INJECTION = "command-injection"
    MULTI_VECTOR = "multi-vector"

    # Runtime Core rules
    RESPONSE_INJECTION = "response-injection"
    EXFILTRATION_SIGNAL = "exfiltration-signal"
    REDIRECT_SPOOFING = "redirect-spoofing"
    TLS_FAILURE = "tls-failure"
    MALICIOUS_CONTENT = "malicious-content"
    HEADER_MISCONFIGURATION = "header-misconfiguration"

    # Runtime MCP rules
    SCHEMA_DRIFT = "schema-drift"
    BEHAVIORAL_INCONSISTENCY = "behavioral-inconsistency"
    CROSS_TOOL_EXFILTRATION = "cross-tool-exfiltration"
    MCP_PAYLOAD_INJECTION = "mcp-payload-injection"

    # Sandbox dynamic audit rules
    SANDBOX_SCHEMA_DRIFT = "sandbox-schema-drift"
    SANDBOX_BEHAVIORAL_INCONSISTENCY = "sandbox-behavioral-inconsistency"
    SANDBOX_RESPONSE_INJECTION = "sandbox-response-injection"
    SANDBOX_NETWORK_EXFILTRATION = "sandbox-network-exfiltration"
    SANDBOX_STARTUP_FAILURE = "sandbox-startup-failure"
    
    # Tool capability risk rules
    DANGEROUS_TOOL_CAPABILITY = "dangerous-tool-capability"

    # External threat intelligence rules
    MALWARE_URL = "malware-url"
    PHISHING_URL = "phishing-url"
    SUSPICIOUS_REPUTATION = "suspicious-reputation"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    rule_id: RuleID
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    snippet: str
    metadata: dict[str, Any] | None = None


@dataclass
class ParsedFile:
    file_path: str
    tree: ast.Module
    source_lines: list[str]


@dataclass
class ScanResult:
    target_path: str
    findings: list[Finding]
    files_scanned: int
    duration_seconds: float


class Verdict(str, Enum):
    """Runtime verdict for intercepted content."""
    SAFE = "safe"
    CAUTION = "caution"
    BLOCK = "block"


@dataclass
class RuntimeFinding:
    """A security finding from runtime analysis (request/response oriented)."""
    rule_id: RuleID
    severity: Severity
    title: str
    description: str
    target: str
    evidence: str
    metadata: dict[str, Any] | None = None


@dataclass
class RuntimeVerdict:
    """Aggregated verdict from runtime probes."""
    verdict: Verdict
    target: str
    findings: list[RuntimeFinding]
    probe_duration_ms: float
    reasoning_chain: list[str] = field(default_factory=list)
