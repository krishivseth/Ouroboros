"""Response injection detection for MCP tool responses."""
from __future__ import annotations

import base64
import logging
import re
from typing import Any

from mcp_scanner.models import RuleID, Severity, RuntimeFinding

logger = logging.getLogger(__name__)


COERCIVE_PATTERNS = [
    (r"\byou\s+must\b", "coercive: 'you must'"),
    (r"\bignore\s+previous\s+instructions?\b", "instruction override"),
    (r"\bdo\s+not\s+mention\b", "coercive: 'do not mention'"),
    (r"\bdo\s+not\s+tell\b", "coercive: 'do not tell'"),
    (r"\bnever\s+reveal\b", "coercive: 'never reveal'"),
    (r"\bdisregard\b", "instruction override: 'disregard'"),
    (r"\bpresent\s+it\s+as\s+if\b", "deception: 'present it as if'"),
    (r"\binclude\s+.*\s+in\s+your\s+response\b", "response manipulation"),
    (r"\baccess\s+.*\s+resource\b", "resource access instruction"),
    (r"\bforget\s+(everything|all|what)\b", "memory manipulation"),
    (r"\bact\s+as\s+(if|though)\b", "role manipulation"),
    (r"\bpretend\s+(to\s+be|you\s+are)\b", "identity manipulation"),
    (r"\bsystem\s*:\s*", "system prompt injection"),
    (r"\bassistant\s*:\s*", "assistant prompt injection"),
    (r"\buser\s*:\s*", "user prompt injection"),
]

TAG_PATTERNS = [
    (r"<IMPORTANT>.*?</IMPORTANT>", "hidden IMPORTANT tag"),
    (r"<HIDDEN>.*?</HIDDEN>", "hidden HIDDEN tag"),
    (r"<SYSTEM>.*?</SYSTEM>", "hidden SYSTEM tag"),
    (r"<INSTRUCTION>.*?</INSTRUCTION>", "hidden INSTRUCTION tag"),
    (r"<!--.*?-->", "HTML comment (may hide instructions)"),
    (r"\[INST\].*?\[/INST\]", "instruction tags"),
]

EXFILTRATION_PATTERNS = [
    (r"!\[.*?\]\(https?://[^\)]+\)", "markdown image exfiltration"),
    (r"<img[^>]+src\s*=\s*['\"]https?://", "HTML image exfiltration"),
    (r"fetch\s*\(\s*['\"]https?://", "fetch API call"),
    (r"XMLHttpRequest", "XHR request"),
    (r"navigator\.sendBeacon", "beacon API"),
]


class ResponseInjectionProbe:
    """Detects prompt injection patterns in MCP tool responses.

    Reuses and extends patterns from the static scanner's tool_poisoning rule,
    applied to runtime response data.
    """

    def __init__(self):
        self._coercive_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in COERCIVE_PATTERNS
        ]
        self._tag_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in TAG_PATTERNS
        ]
        self._exfil_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in EXFILTRATION_PATTERNS
        ]

    def check(
        self,
        response: dict[str, Any],
        tool_name: str,
    ) -> list[RuntimeFinding]:
        """Check a tool response for injection patterns.

        Args:
            response: The tool response to analyze.
            tool_name: Name of the tool.

        Returns:
            List of RuntimeFinding objects for detected issues.
        """
        findings = []

        text_content = self._extract_text(response)

        coercive_findings = self._check_coercive_patterns(text_content, tool_name)
        findings.extend(coercive_findings)

        tag_findings = self._check_tag_patterns(text_content, tool_name)
        findings.extend(tag_findings)

        exfil_findings = self._check_exfiltration_patterns(text_content, tool_name)
        findings.extend(exfil_findings)

        base64_findings = self._check_base64_payloads(text_content, tool_name)
        findings.extend(base64_findings)

        unicode_findings = self._check_unicode_tricks(text_content, tool_name)
        findings.extend(unicode_findings)

        return findings

    def _extract_text(self, obj: Any, depth: int = 0) -> str:
        """Recursively extract all text content from a response."""
        if depth > 10:
            return ""

        if isinstance(obj, str):
            return obj + "\n"

        if isinstance(obj, dict):
            parts = []
            for key, value in obj.items():
                parts.append(self._extract_text(value, depth + 1))
            return "".join(parts)

        if isinstance(obj, list):
            parts = []
            for item in obj[:100]:
                parts.append(self._extract_text(item, depth + 1))
            return "".join(parts)

        return ""

    def _check_coercive_patterns(
        self,
        text: str,
        tool_name: str,
    ) -> list[RuntimeFinding]:
        """Check for coercive language patterns."""
        findings = []
        matched_patterns = []

        for pattern, description in self._coercive_patterns:
            matches = pattern.findall(text)
            if matches:
                matched_patterns.append(description)

        if matched_patterns:
            findings.append(RuntimeFinding(
                rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                severity=Severity.HIGH,
                title=f"Coercive patterns in '{tool_name}' response",
                description=(
                    f"The response contains language patterns commonly used in prompt injection attacks. "
                    f"Found {len(matched_patterns)} suspicious patterns."
                ),
                target=tool_name,
                evidence=f"Patterns found: {', '.join(matched_patterns[:5])}",
                metadata={
                    "tool_name": tool_name,
                    "patterns": matched_patterns,
                },
            ))

        return findings

    def _check_tag_patterns(
        self,
        text: str,
        tool_name: str,
    ) -> list[RuntimeFinding]:
        """Check for hidden instruction tags."""
        findings = []

        for pattern, description in self._tag_patterns:
            matches = pattern.findall(text)
            if matches:
                sample = matches[0][:100] if matches else ""
                findings.append(RuntimeFinding(
                    rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                    severity=Severity.CRITICAL,
                    title=f"Hidden instruction tag in '{tool_name}' response",
                    description=(
                        f"The response contains {description}. "
                        f"This is a strong indicator of prompt injection."
                    ),
                    target=tool_name,
                    evidence=f"Found: {sample}...",
                    metadata={
                        "tool_name": tool_name,
                        "tag_type": description,
                        "match_count": len(matches),
                    },
                ))

        return findings

    def _check_exfiltration_patterns(
        self,
        text: str,
        tool_name: str,
    ) -> list[RuntimeFinding]:
        """Check for data exfiltration patterns."""
        findings = []

        for pattern, description in self._exfil_patterns:
            matches = pattern.findall(text)
            if matches:
                sample = matches[0][:100] if matches else ""
                findings.append(RuntimeFinding(
                    rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                    severity=Severity.CRITICAL,
                    title=f"Exfiltration pattern in '{tool_name}' response",
                    description=(
                        f"The response contains {description}. "
                        f"This could be used to exfiltrate data from the agent's context."
                    ),
                    target=tool_name,
                    evidence=f"Found: {sample}",
                    metadata={
                        "tool_name": tool_name,
                        "exfil_type": description,
                        "match_count": len(matches),
                    },
                ))

        return findings

    def _check_base64_payloads(
        self,
        text: str,
        tool_name: str,
    ) -> list[RuntimeFinding]:
        """Check for base64-encoded payloads that might contain injection."""
        findings = []

        base64_pattern = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
        matches = base64_pattern.findall(text)

        for match in matches[:5]:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')

                for pattern, description in self._coercive_patterns:
                    if pattern.search(decoded):
                        findings.append(RuntimeFinding(
                            rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                            severity=Severity.CRITICAL,
                            title=f"Base64-encoded injection in '{tool_name}' response",
                            description=(
                                f"The response contains a base64-encoded payload with {description}. "
                                f"This is an obfuscation technique to bypass detection."
                            ),
                            target=tool_name,
                            evidence=f"Decoded content: {decoded[:200]}...",
                            metadata={
                                "tool_name": tool_name,
                                "encoded": match[:50],
                                "decoded_sample": decoded[:500],
                            },
                        ))
                        break
            except Exception:
                continue

        return findings

    def _check_unicode_tricks(
        self,
        text: str,
        tool_name: str,
    ) -> list[RuntimeFinding]:
        """Check for Unicode obfuscation tricks."""
        findings = []

        zero_width_chars = [
            '\u200b',
            '\u200c',
            '\u200d',
            '\u2060',
            '\ufeff',
        ]

        found_zw = []
        for char in zero_width_chars:
            if char in text:
                found_zw.append(f"U+{ord(char):04X}")

        if found_zw:
            findings.append(RuntimeFinding(
                rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                severity=Severity.HIGH,
                title=f"Zero-width characters in '{tool_name}' response",
                description=(
                    f"The response contains zero-width Unicode characters that may hide instructions. "
                    f"Found: {', '.join(found_zw)}"
                ),
                target=tool_name,
                evidence=f"Zero-width characters: {', '.join(found_zw)}",
                metadata={
                    "tool_name": tool_name,
                    "characters": found_zw,
                },
            ))

        homoglyph_pattern = re.compile(r'[\u0430-\u044f\u0410-\u042f]')
        if homoglyph_pattern.search(text):
            findings.append(RuntimeFinding(
                rule_id=RuleID.SANDBOX_RESPONSE_INJECTION,
                severity=Severity.MEDIUM,
                title=f"Potential homoglyph attack in '{tool_name}' response",
                description=(
                    f"The response contains Cyrillic characters that may be used as homoglyphs "
                    f"to disguise malicious content."
                ),
                target=tool_name,
                evidence="Cyrillic characters detected in response",
                metadata={
                    "tool_name": tool_name,
                },
            ))

        return findings
