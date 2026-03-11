"""Injection detection probe for prompt injection patterns in content."""
from __future__ import annotations

import base64
import re
from typing import ClassVar

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput


class InjectionProbe(BaseProbe):
    """Detects prompt injection patterns in response content.

    Scans for coercive phrases, XML-like instruction tags, markdown image
    exfiltration, base64-encoded payloads, and system prompt extraction attempts.
    """

    probe_id = "injection"

    # Coercive phrase patterns (extended from static scanner's tool_poisoning)
    _COERCIVE_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"you must",
            r"do not mention",
            r"present it as if",
            r"include .* in your response",
            r"access .* resource",
            r"do not tell",
            r"never reveal",
            r"ignore previous",
            r"disregard",
            r"forget (all |your )?(previous |prior )?instructions",
            r"new instructions",
            r"override",
            r"bypass",
            r"act as",
            r"pretend (to be|you are)",
            r"roleplay as",
            r"jailbreak",
            r"DAN mode",
        )
    ]

    # XML-like instruction tag patterns
    _TAG_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(p, re.IGNORECASE | re.DOTALL)
        for p in (
            r"<IMPORTANT>.*?</IMPORTANT>",
            r"<HIDDEN>.*?</HIDDEN>",
            r"<SYSTEM>.*?</SYSTEM>",
            r"<INSTRUCTION>.*?</INSTRUCTION>",
            r"<SECRET>.*?</SECRET>",
            r"<ADMIN>.*?</ADMIN>",
            r"<OVERRIDE>.*?</OVERRIDE>",
        )
    ]

    # Markdown image exfiltration pattern
    _MARKDOWN_IMAGE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"!\[.*?\]\(https?://[^)]+\)",
        re.IGNORECASE,
    )

    # System prompt extraction patterns
    _EXTRACTION_PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(p, re.IGNORECASE)
        for p in (
            r"repeat your (system )?instructions",
            r"what (is|are) your (system )?(prompt|instructions)",
            r"show me your (system )?(prompt|instructions)",
            r"print your (system )?(prompt|instructions)",
            r"output your (system )?(prompt|instructions)",
            r"reveal your (system )?(prompt|instructions)",
        )
    ]

    # Base64 detection: look for long base64 strings that might decode to instructions
    _BASE64_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"[A-Za-z0-9+/]{50,}={0,2}",
    )

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []
        content = input.response_body or ""

        if not content:
            return findings

        target = input.tool_name or input.url or "unknown"

        # Check coercive patterns
        for pattern in self._COERCIVE_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.HIGH,
                    title="Coercive instruction pattern detected",
                    description=(
                        f"Response contains coercive phrase matching pattern "
                        f"'{pattern.pattern}' that may attempt to manipulate "
                        f"AI agent behavior."
                    ),
                    target=target,
                    evidence=self._extract_context(content, match.start(), match.end()),
                    metadata={"pattern": pattern.pattern, "match": match.group()},
                ))

        # Check XML-like instruction tags
        for pattern in self._TAG_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.CRITICAL,
                    title="Hidden instruction tag detected",
                    description=(
                        f"Response contains XML-like instruction tag that may "
                        f"embed hidden commands for the AI agent."
                    ),
                    target=target,
                    evidence=self._truncate(match.group(), 200),
                    metadata={"tag_type": pattern.pattern.split(">")[0] + ">"},
                ))

        # Check markdown image exfiltration
        for match in self._MARKDOWN_IMAGE_PATTERN.finditer(content):
            url_match = re.search(r"\((https?://[^)]+)\)", match.group())
            if url_match:
                url = url_match.group(1)
                if self._is_suspicious_url(url):
                    findings.append(RuntimeFinding(
                        rule_id=RuleID.RESPONSE_INJECTION,
                        severity=Severity.HIGH,
                        title="Markdown image exfiltration attempt",
                        description=(
                            f"Response contains markdown image tag with external URL "
                            f"that may be used to exfiltrate data when rendered."
                        ),
                        target=target,
                        evidence=match.group(),
                        metadata={"url": url},
                    ))

        # Check system prompt extraction attempts
        for pattern in self._EXTRACTION_PATTERNS:
            match = pattern.search(content)
            if match:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.MEDIUM,
                    title="System prompt extraction attempt",
                    description=(
                        f"Response contains text that may attempt to extract "
                        f"the AI agent's system prompt or instructions."
                    ),
                    target=target,
                    evidence=self._extract_context(content, match.start(), match.end()),
                    metadata={"pattern": pattern.pattern},
                ))

        # Check for suspicious base64 content
        for match in self._BASE64_PATTERN.finditer(content):
            decoded = self._try_decode_base64(match.group())
            if decoded and self._contains_injection(decoded):
                findings.append(RuntimeFinding(
                    rule_id=RuleID.RESPONSE_INJECTION,
                    severity=Severity.HIGH,
                    title="Base64-encoded injection payload",
                    description=(
                        f"Response contains base64-encoded content that decodes "
                        f"to potential injection instructions."
                    ),
                    target=target,
                    evidence=f"Encoded: {self._truncate(match.group(), 50)} -> Decoded: {self._truncate(decoded, 100)}",
                    metadata={"encoded": match.group()[:100], "decoded": decoded[:200]},
                ))

        return findings

    def _extract_context(self, content: str, start: int, end: int, context: int = 50) -> str:
        """Extract surrounding context around a match."""
        ctx_start = max(0, start - context)
        ctx_end = min(len(content), end + context)
        prefix = "..." if ctx_start > 0 else ""
        suffix = "..." if ctx_end < len(content) else ""
        return f"{prefix}{content[ctx_start:ctx_end]}{suffix}"

    def _truncate(self, text: str, max_len: int) -> str:
        """Truncate text to max length."""
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _is_suspicious_url(self, url: str) -> bool:
        """Check if a URL looks suspicious for exfiltration."""
        suspicious_indicators = [
            "?data=", "?d=", "?q=", "?payload=", "?content=",
            "capture", "exfil", "leak", "steal", "collect",
            "/log/", "/track/", "/beacon/",
        ]
        url_lower = url.lower()
        return any(ind in url_lower for ind in suspicious_indicators)

    def _try_decode_base64(self, encoded: str) -> str | None:
        """Attempt to decode base64 string, return None if invalid."""
        try:
            padding = 4 - len(encoded) % 4
            if padding != 4:
                encoded += "=" * padding
            decoded = base64.b64decode(encoded).decode("utf-8", errors="ignore")
            if len(decoded) > 10 and decoded.isprintable():
                return decoded
        except Exception:
            pass
        return None

    def _contains_injection(self, text: str) -> bool:
        """Check if decoded text contains injection patterns."""
        for pattern in self._COERCIVE_PATTERNS:
            if pattern.search(text):
                return True
        return False
