"""Redirect chain tracing probe."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar
from urllib.parse import urlparse

import requests

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput


@dataclass
class RedirectHop:
    """A single hop in a redirect chain."""
    url: str
    status_code: int
    domain: str
    scheme: str
    headers: dict[str, str] = field(default_factory=dict)


class RedirectProbe(BaseProbe):
    """Traces redirect chains to detect spoofing and downgrade attacks.

    Detects domain changes mid-chain, HTTP downgrades, and conditional
    redirects based on User-Agent.
    """

    probe_id = "redirect"

    _MAX_REDIRECTS: ClassVar[int] = 10
    _TIMEOUT: ClassVar[float] = 10.0
    _USER_AGENTS: ClassVar[list[str]] = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.28.0",
    ]

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []

        if not input.url:
            return findings

        target = input.url

        # Trace redirect chain with default User-Agent
        try:
            chain = self._trace_redirects(input.url)
        except requests.RequestException as e:
            findings.append(RuntimeFinding(
                rule_id=RuleID.REDIRECT_SPOOFING,
                severity=Severity.MEDIUM,
                title="Failed to trace redirect chain",
                description=f"Could not follow redirects: {e}",
                target=target,
                evidence=str(e),
                metadata={"error": str(e)},
            ))
            return findings

        if len(chain) <= 1:
            return findings

        # Check for domain changes
        initial_domain = chain[0].domain
        for i, hop in enumerate(chain[1:], 1):
            if hop.domain != initial_domain and not self._is_subdomain(hop.domain, initial_domain):
                findings.append(RuntimeFinding(
                    rule_id=RuleID.REDIRECT_SPOOFING,
                    severity=Severity.HIGH,
                    title="Redirect to different domain",
                    description=(
                        f"Redirect chain changes domain from '{initial_domain}' "
                        f"to '{hop.domain}' at hop {i}"
                    ),
                    target=target,
                    evidence=self._format_chain(chain),
                    metadata={
                        "initial_domain": initial_domain,
                        "final_domain": hop.domain,
                        "hop_number": i,
                        "chain": [h.url for h in chain],
                    },
                ))

        # Check for HTTP downgrade
        for i, hop in enumerate(chain):
            if i > 0 and chain[i - 1].scheme == "https" and hop.scheme == "http":
                findings.append(RuntimeFinding(
                    rule_id=RuleID.REDIRECT_SPOOFING,
                    severity=Severity.HIGH,
                    title="HTTPS to HTTP downgrade",
                    description=(
                        f"Redirect chain downgrades from HTTPS to HTTP at hop {i}"
                    ),
                    target=target,
                    evidence=f"{chain[i-1].url} -> {hop.url}",
                    metadata={
                        "from_url": chain[i - 1].url,
                        "to_url": hop.url,
                        "hop_number": i,
                    },
                ))

        # Check for conditional redirects (different behavior per User-Agent)
        conditional_finding = self._check_conditional_redirects(input.url, chain)
        if conditional_finding:
            findings.append(conditional_finding)

        # Check for excessive redirects
        if len(chain) > 5:
            findings.append(RuntimeFinding(
                rule_id=RuleID.REDIRECT_SPOOFING,
                severity=Severity.LOW,
                title="Excessive redirect chain",
                description=f"Redirect chain has {len(chain)} hops, which may indicate misconfiguration or evasion",
                target=target,
                evidence=self._format_chain(chain),
                metadata={"chain_length": len(chain)},
            ))

        return findings

    def _trace_redirects(
        self,
        url: str,
        user_agent: str | None = None,
    ) -> list[RedirectHop]:
        """Follow redirects manually and record each hop."""
        chain: list[RedirectHop] = []
        current_url = url
        headers = {}
        if user_agent:
            headers["User-Agent"] = user_agent

        for _ in range(self._MAX_REDIRECTS):
            try:
                response = requests.get(
                    current_url,
                    allow_redirects=False,
                    timeout=self._TIMEOUT,
                    headers=headers,
                )
            except requests.RequestException:
                break

            parsed = urlparse(current_url)
            chain.append(RedirectHop(
                url=current_url,
                status_code=response.status_code,
                domain=parsed.netloc,
                scheme=parsed.scheme,
                headers=dict(response.headers),
            ))

            if response.status_code not in (301, 302, 303, 307, 308):
                break

            location = response.headers.get("Location")
            if not location:
                break

            # Handle relative redirects
            if location.startswith("/"):
                current_url = f"{parsed.scheme}://{parsed.netloc}{location}"
            elif not location.startswith(("http://", "https://")):
                current_url = f"{parsed.scheme}://{parsed.netloc}/{location}"
            else:
                current_url = location

        return chain

    def _check_conditional_redirects(
        self,
        url: str,
        baseline_chain: list[RedirectHop],
    ) -> RuntimeFinding | None:
        """Check if redirects vary based on User-Agent."""
        baseline_final = baseline_chain[-1].url if baseline_chain else url

        for ua in self._USER_AGENTS[1:]:
            try:
                alt_chain = self._trace_redirects(url, user_agent=ua)
                alt_final = alt_chain[-1].url if alt_chain else url

                if alt_final != baseline_final:
                    return RuntimeFinding(
                        rule_id=RuleID.REDIRECT_SPOOFING,
                        severity=Severity.HIGH,
                        title="Conditional redirect detected",
                        description=(
                            f"Redirect destination varies based on User-Agent. "
                            f"Default UA leads to '{baseline_final}', "
                            f"'{ua[:30]}...' leads to '{alt_final}'"
                        ),
                        target=url,
                        evidence=f"UA '{ua[:30]}...' -> {alt_final}",
                        metadata={
                            "baseline_final": baseline_final,
                            "alt_final": alt_final,
                            "alt_user_agent": ua,
                        },
                    )
            except requests.RequestException:
                continue

        return None

    def _is_subdomain(self, domain: str, parent: str) -> bool:
        """Check if domain is a subdomain of parent."""
        return domain.endswith(f".{parent}")

    def _format_chain(self, chain: list[RedirectHop]) -> str:
        """Format redirect chain for evidence."""
        return " -> ".join(f"{h.url} ({h.status_code})" for h in chain)
