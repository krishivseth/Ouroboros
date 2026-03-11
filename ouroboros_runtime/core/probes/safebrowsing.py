"""Google Safe Browsing probe for malware and phishing URL detection."""
from __future__ import annotations

import logging
import os
from typing import ClassVar

import requests

from mcp_scanner.models import RuleID, RuntimeFinding, Severity

from .base import BaseProbe, ProbeInput

logger = logging.getLogger(__name__)

SAFE_BROWSING_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


class SafeBrowsingProbe(BaseProbe):
    """Checks URLs against Google Safe Browsing threat lists.

    Uses the v4 Lookup API to check for:
    - MALWARE
    - SOCIAL_ENGINEERING (phishing)
    - UNWANTED_SOFTWARE

    Requires GOOGLE_SAFE_BROWSING_API_KEY environment variable.
    """

    probe_id = "safebrowsing"

    _THREAT_TYPE_MAP: ClassVar[dict[str, tuple[RuleID, Severity, str]]] = {
        "MALWARE": (
            RuleID.MALWARE_URL,
            Severity.CRITICAL,
            "URL is flagged as distributing malware",
        ),
        "SOCIAL_ENGINEERING": (
            RuleID.PHISHING_URL,
            Severity.CRITICAL,
            "URL is flagged as a phishing/deceptive site",
        ),
        "UNWANTED_SOFTWARE": (
            RuleID.MALWARE_URL,
            Severity.HIGH,
            "URL is flagged as distributing unwanted software",
        ),
    }

    def __init__(self) -> None:
        self._api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")

    @property
    def is_available(self) -> bool:
        """Check if the probe has required credentials."""
        return bool(self._api_key)

    def run(self, input: ProbeInput) -> list[RuntimeFinding]:
        findings: list[RuntimeFinding] = []

        if not input.url:
            return findings

        if not self._api_key:
            logger.debug("SafeBrowsingProbe skipped: no API key configured")
            return findings

        try:
            matches = self._check_url(input.url)
            for match in matches:
                threat_type = match.get("threatType", "UNKNOWN")
                if threat_type in self._THREAT_TYPE_MAP:
                    rule_id, severity, description = self._THREAT_TYPE_MAP[threat_type]
                    findings.append(
                        RuntimeFinding(
                            rule_id=rule_id,
                            severity=severity,
                            title=f"Google Safe Browsing: {threat_type}",
                            description=description,
                            target=input.url,
                            evidence=f"Threat type: {threat_type}, Platform: {match.get('platformType', 'ANY')}",
                            metadata={
                                "source": "google_safe_browsing",
                                "threat_type": threat_type,
                                "platform_type": match.get("platformType"),
                                "cache_duration": match.get("cacheDuration"),
                            },
                        )
                    )
        except requests.RequestException as e:
            logger.warning("SafeBrowsingProbe request failed: %s", e)
        except Exception as e:
            logger.exception("SafeBrowsingProbe error: %s", e)

        return findings

    def _check_url(self, url: str) -> list[dict]:
        """Query Google Safe Browsing API for threat matches."""
        payload = {
            "client": {
                "clientId": "ouroboros-security",
                "clientVersion": "1.0.0",
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        response = requests.post(
            SAFE_BROWSING_API_URL,
            params={"key": self._api_key},
            json=payload,
            timeout=10,
        )
        response.raise_for_status()

        data = response.json()
        return data.get("matches", [])
