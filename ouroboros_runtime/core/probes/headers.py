"""Response header analysis probe."""
from __future__ import annotations

import re
from typing import ClassVar

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput


class HeadersProbe(BaseProbe):
    """Analyzes HTTP response headers for security misconfigurations.

    Checks for missing security headers, permissive CORS, and server
    information leakage.
    """

    probe_id = "headers"

    _SECURITY_HEADERS: ClassVar[dict[str, tuple[Severity, str]]] = {
        "content-security-policy": (
            Severity.MEDIUM,
            "Content-Security-Policy header is missing, allowing potential XSS attacks",
        ),
        "x-content-type-options": (
            Severity.LOW,
            "X-Content-Type-Options header is missing, allowing MIME type sniffing",
        ),
        "strict-transport-security": (
            Severity.MEDIUM,
            "Strict-Transport-Security header is missing, allowing protocol downgrade attacks",
        ),
        "x-frame-options": (
            Severity.LOW,
            "X-Frame-Options header is missing, allowing clickjacking attacks",
        ),
        "x-xss-protection": (
            Severity.INFO,
            "X-XSS-Protection header is missing (deprecated but still useful for older browsers)",
        ),
    }

    _SERVER_VERSION_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(apache|nginx|iis|tomcat|jetty|express|gunicorn|uvicorn|werkzeug)"
        r"[/\s]*([\d.]+)?",
        re.IGNORECASE,
    )

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []

        if not input.response_headers:
            return findings

        target = input.url or input.tool_name or "unknown"
        headers_lower = {k.lower(): v for k, v in input.response_headers.items()}

        # Check for missing security headers
        for header, (severity, description) in self._SECURITY_HEADERS.items():
            if header not in headers_lower:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.HEADER_MISCONFIGURATION,
                    severity=severity,
                    title=f"Missing {header} header",
                    description=description,
                    target=target,
                    evidence=f"Header '{header}' not present in response",
                    metadata={"missing_header": header},
                ))

        # Check for permissive CORS
        cors_origin = headers_lower.get("access-control-allow-origin")
        if cors_origin == "*":
            findings.append(RuntimeFinding(
                rule_id=RuleID.HEADER_MISCONFIGURATION,
                severity=Severity.MEDIUM,
                title="Permissive CORS configuration",
                description=(
                    "Access-Control-Allow-Origin is set to '*', allowing any "
                    "origin to make cross-origin requests"
                ),
                target=target,
                evidence="Access-Control-Allow-Origin: *",
                metadata={"cors_origin": cors_origin},
            ))

        cors_credentials = headers_lower.get("access-control-allow-credentials")
        if cors_credentials and cors_credentials.lower() == "true" and cors_origin == "*":
            findings.append(RuntimeFinding(
                rule_id=RuleID.HEADER_MISCONFIGURATION,
                severity=Severity.HIGH,
                title="Dangerous CORS configuration",
                description=(
                    "CORS allows credentials with wildcard origin, which is a "
                    "security vulnerability"
                ),
                target=target,
                evidence="Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
                metadata={"cors_origin": cors_origin, "cors_credentials": cors_credentials},
            ))

        # Check for server version leakage
        server_header = headers_lower.get("server", "")
        if server_header:
            match = self._SERVER_VERSION_PATTERN.search(server_header)
            if match and match.group(2):
                findings.append(RuntimeFinding(
                    rule_id=RuleID.HEADER_MISCONFIGURATION,
                    severity=Severity.LOW,
                    title="Server version disclosure",
                    description=(
                        f"Server header reveals software version: {server_header}. "
                        f"This information can help attackers identify vulnerabilities."
                    ),
                    target=target,
                    evidence=f"Server: {server_header}",
                    metadata={"server": match.group(1), "version": match.group(2)},
                ))

        # Check X-Powered-By header
        powered_by = headers_lower.get("x-powered-by")
        if powered_by:
            findings.append(RuntimeFinding(
                rule_id=RuleID.HEADER_MISCONFIGURATION,
                severity=Severity.LOW,
                title="Technology stack disclosure",
                description=(
                    f"X-Powered-By header reveals technology: {powered_by}. "
                    f"This information can help attackers target specific vulnerabilities."
                ),
                target=target,
                evidence=f"X-Powered-By: {powered_by}",
                metadata={"powered_by": powered_by},
            ))

        # Check for insecure cookie settings
        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            cookie_lower = set_cookie.lower()
            issues = []
            if "secure" not in cookie_lower:
                issues.append("missing Secure flag")
            if "httponly" not in cookie_lower:
                issues.append("missing HttpOnly flag")
            if "samesite" not in cookie_lower:
                issues.append("missing SameSite attribute")

            if issues:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.HEADER_MISCONFIGURATION,
                    severity=Severity.MEDIUM,
                    title="Insecure cookie configuration",
                    description=f"Cookie has security issues: {', '.join(issues)}",
                    target=target,
                    evidence=f"Set-Cookie: {set_cookie[:100]}...",
                    metadata={"issues": issues},
                ))

        return findings
