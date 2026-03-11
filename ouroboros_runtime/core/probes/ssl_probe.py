"""SSL/TLS validation probe."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import ClassVar
from urllib.parse import urlparse

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput


class SSLProbe(BaseProbe):
    """Validates TLS certificates for endpoints.

    Checks certificate chain, expiration, hostname match, and cipher strength.
    """

    probe_id = "ssl"

    _WEAK_CIPHERS: ClassVar[set[str]] = {
        "DES", "3DES", "RC4", "RC2", "MD5", "NULL", "EXPORT", "anon",
    }

    _DEFAULT_TIMEOUT: ClassVar[float] = 10.0

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []

        if not input.url:
            return findings

        parsed = urlparse(input.url)
        if parsed.scheme != "https":
            return findings

        host = parsed.hostname
        port = parsed.port or 443

        if not host:
            return findings

        target = input.url

        try:
            cert_info = self._get_certificate_info(host, port)
        except ssl.SSLCertVerificationError as e:
            findings.append(RuntimeFinding(
                rule_id=RuleID.TLS_FAILURE,
                severity=Severity.CRITICAL,
                title="SSL certificate verification failed",
                description=f"Certificate verification failed: {e}",
                target=target,
                evidence=str(e),
                metadata={"error_type": "verification", "host": host, "port": port},
            ))
            return findings
        except ssl.SSLError as e:
            findings.append(RuntimeFinding(
                rule_id=RuleID.TLS_FAILURE,
                severity=Severity.HIGH,
                title="SSL connection error",
                description=f"SSL error connecting to {host}:{port}: {e}",
                target=target,
                evidence=str(e),
                metadata={"error_type": "connection", "host": host, "port": port},
            ))
            return findings
        except (socket.timeout, socket.error) as e:
            findings.append(RuntimeFinding(
                rule_id=RuleID.TLS_FAILURE,
                severity=Severity.MEDIUM,
                title="Connection failed",
                description=f"Could not connect to {host}:{port}: {e}",
                target=target,
                evidence=str(e),
                metadata={"error_type": "socket", "host": host, "port": port},
            ))
            return findings

        # Check certificate expiration
        if cert_info.get("not_after"):
            not_after = cert_info["not_after"]
            now = datetime.now(timezone.utc)
            if not_after < now:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.TLS_FAILURE,
                    severity=Severity.CRITICAL,
                    title="SSL certificate expired",
                    description=f"Certificate expired on {not_after.isoformat()}",
                    target=target,
                    evidence=f"Expired: {not_after.isoformat()}, Now: {now.isoformat()}",
                    metadata={"expired_on": not_after.isoformat()},
                ))
            elif (not_after - now).days < 30:
                findings.append(RuntimeFinding(
                    rule_id=RuleID.TLS_FAILURE,
                    severity=Severity.LOW,
                    title="SSL certificate expiring soon",
                    description=f"Certificate expires in {(not_after - now).days} days",
                    target=target,
                    evidence=f"Expires: {not_after.isoformat()}",
                    metadata={"expires_on": not_after.isoformat(), "days_remaining": (not_after - now).days},
                ))

        # Check hostname match
        if cert_info.get("subject_cn") and cert_info.get("san"):
            if not self._hostname_matches(host, cert_info["subject_cn"], cert_info["san"]):
                findings.append(RuntimeFinding(
                    rule_id=RuleID.TLS_FAILURE,
                    severity=Severity.CRITICAL,
                    title="SSL certificate hostname mismatch",
                    description=f"Certificate CN/SAN does not match hostname '{host}'",
                    target=target,
                    evidence=f"Host: {host}, CN: {cert_info['subject_cn']}, SAN: {cert_info['san']}",
                    metadata={"host": host, "cn": cert_info["subject_cn"], "san": cert_info["san"]},
                ))

        # Check cipher strength
        if cert_info.get("cipher"):
            cipher_name = cert_info["cipher"][0] if cert_info["cipher"] else ""
            for weak in self._WEAK_CIPHERS:
                if weak.upper() in cipher_name.upper():
                    findings.append(RuntimeFinding(
                        rule_id=RuleID.TLS_FAILURE,
                        severity=Severity.HIGH,
                        title="Weak SSL cipher in use",
                        description=f"Connection uses weak cipher: {cipher_name}",
                        target=target,
                        evidence=f"Cipher: {cipher_name}",
                        metadata={"cipher": cipher_name, "weak_component": weak},
                    ))
                    break

        # Check protocol version
        if cert_info.get("version"):
            version = cert_info["version"]
            if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"):
                findings.append(RuntimeFinding(
                    rule_id=RuleID.TLS_FAILURE,
                    severity=Severity.HIGH,
                    title="Outdated TLS protocol version",
                    description=f"Connection uses deprecated protocol: {version}",
                    target=target,
                    evidence=f"Protocol: {version}",
                    metadata={"protocol": version},
                ))

        return findings

    def _get_certificate_info(self, host: str, port: int) -> dict:
        """Retrieve certificate information from the server."""
        context = ssl.create_default_context()
        info: dict = {}

        with socket.create_connection((host, port), timeout=self._DEFAULT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                info["cipher"] = ssock.cipher()
                info["version"] = ssock.version()

                if cert:
                    # Parse expiration
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        info["not_after"] = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)

                    # Parse subject CN
                    subject = cert.get("subject", ())
                    for rdn in subject:
                        for attr, value in rdn:
                            if attr == "commonName":
                                info["subject_cn"] = value
                                break

                    # Parse SAN
                    san = cert.get("subjectAltName", ())
                    info["san"] = [value for type_, value in san if type_ == "DNS"]

        return info

    def _hostname_matches(self, hostname: str, cn: str | None, san: list[str]) -> bool:
        """Check if hostname matches certificate CN or SAN entries."""
        hostname = hostname.lower()

        # Check SAN first (preferred)
        for name in san:
            if self._match_hostname_pattern(hostname, name.lower()):
                return True

        # Fall back to CN
        if cn and self._match_hostname_pattern(hostname, cn.lower()):
            return True

        return False

    def _match_hostname_pattern(self, hostname: str, pattern: str) -> bool:
        """Match hostname against a pattern (supports wildcards)."""
        if pattern.startswith("*."):
            suffix = pattern[2:]
            parts = hostname.split(".", 1)
            return len(parts) == 2 and parts[1] == suffix
        return hostname == pattern
