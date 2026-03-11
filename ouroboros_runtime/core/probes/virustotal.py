"""VirusTotal probe for URL reputation checking."""
from __future__ import annotations

import base64
import logging
import os
import time
from typing import Any, ClassVar

import requests

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"


class VirusTotalProbe(BaseProbe):
    """Checks URL reputation using VirusTotal API.

    Uses the v3 API to get URL analysis reports from 70+ security vendors.

    Requires VIRUSTOTAL_API_KEY environment variable.

    Note: Public API is limited to 4 requests/minute and 500 requests/day.
    """

    probe_id = "virustotal"

    _MALICIOUS_THRESHOLD: ClassVar[int] = 1
    _SUSPICIOUS_THRESHOLD: ClassVar[int] = 3

    _last_request_time: ClassVar[float] = 0
    _MIN_REQUEST_INTERVAL: ClassVar[float] = 15.0  # 4 req/min = 15s between requests

    def __init__(self) -> None:
        self._api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")

    @property
    def is_available(self) -> bool:
        """Check if the probe has required credentials."""
        return bool(self._api_key)

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []

        if not input.url:
            return findings

        if not self._api_key:
            logger.debug("VirusTotalProbe skipped: no API key configured")
            return findings

        self._rate_limit()

        try:
            report = self._get_url_report(input.url)
            if report:
                findings.extend(self._analyze_report(input.url, report))
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                logger.debug("URL not found in VirusTotal database: %s", input.url)
            elif e.response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
            else:
                logger.warning("VirusTotal API error: %s", e)
        except requests.RequestException as e:
            logger.warning("VirusTotalProbe request failed: %s", e)
        except Exception as e:
            logger.exception("VirusTotalProbe error: %s", e)

        return findings

    def _rate_limit(self) -> None:
        """Enforce rate limiting for public API."""
        now = time.time()
        elapsed = now - VirusTotalProbe._last_request_time
        if elapsed < self._MIN_REQUEST_INTERVAL:
            sleep_time = self._MIN_REQUEST_INTERVAL - elapsed
            logger.debug("Rate limiting: sleeping %.1fs", sleep_time)
            time.sleep(sleep_time)
        VirusTotalProbe._last_request_time = time.time()

    def _url_to_id(self, url: str) -> str:
        """Convert URL to VirusTotal URL identifier (base64 without padding)."""
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def _get_url_report(self, url: str) -> dict[str, Any] | None:
        """Fetch URL report from VirusTotal."""
        url_id = self._url_to_id(url)
        response = requests.get(
            f"{VIRUSTOTAL_API_URL}/urls/{url_id}",
            headers={"x-apikey": self._api_key},
            timeout=15,
        )
        response.raise_for_status()
        return response.json().get("data", {}).get("attributes", {})

    def _analyze_report(
        self, url: str, report: dict[str, Any]
    ) -> list[RuntimeFinding]:
        """Analyze VirusTotal report and generate findings."""
        findings: list[RuntimeFinding] = []

        stats = report.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        if malicious >= self._MALICIOUS_THRESHOLD:
            severity = Severity.CRITICAL if malicious >= 5 else Severity.HIGH
            findings.append(
                RuntimeFinding(
                    rule_id=RuleID.SUSPICIOUS_REPUTATION,
                    severity=severity,
                    title=f"VirusTotal: {malicious} vendors flagged as malicious",
                    description=(
                        f"URL was flagged as malicious by {malicious} out of {total} "
                        f"security vendors on VirusTotal."
                    ),
                    target=url,
                    evidence=self._format_evidence(report, stats),
                    metadata={
                        "source": "virustotal",
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_vendors": total,
                        "categories": report.get("categories", {}),
                        "last_analysis_date": report.get("last_analysis_date"),
                    },
                )
            )
        elif suspicious >= self._SUSPICIOUS_THRESHOLD:
            findings.append(
                RuntimeFinding(
                    rule_id=RuleID.SUSPICIOUS_REPUTATION,
                    severity=Severity.MEDIUM,
                    title=f"VirusTotal: {suspicious} vendors flagged as suspicious",
                    description=(
                        f"URL was flagged as suspicious by {suspicious} out of {total} "
                        f"security vendors on VirusTotal."
                    ),
                    target=url,
                    evidence=self._format_evidence(report, stats),
                    metadata={
                        "source": "virustotal",
                        "malicious_count": malicious,
                        "suspicious_count": suspicious,
                        "total_vendors": total,
                        "categories": report.get("categories", {}),
                    },
                )
            )

        return findings

    def _format_evidence(
        self, report: dict[str, Any], stats: dict[str, int]
    ) -> str:
        """Format evidence string from report data."""
        parts = [
            f"Malicious: {stats.get('malicious', 0)}",
            f"Suspicious: {stats.get('suspicious', 0)}",
            f"Harmless: {stats.get('harmless', 0)}",
            f"Undetected: {stats.get('undetected', 0)}",
        ]

        categories = report.get("categories", {})
        if categories:
            cat_list = list(categories.values())[:3]
            parts.append(f"Categories: {', '.join(cat_list)}")

        return " | ".join(parts)
