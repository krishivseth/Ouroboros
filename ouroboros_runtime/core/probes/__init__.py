"""Security probes for runtime content validation."""
from __future__ import annotations

import os

from .base import BaseProbe, ProbeInput
from .injection import InjectionProbe
from .ssl_probe import SSLProbe
from .headers import HeadersProbe
from .redirect import RedirectProbe
from .content import ContentProbe
from .safebrowsing import SafeBrowsingProbe
from .virustotal import VirusTotalProbe

# Core probes that always run (no external dependencies)
CORE_PROBES: list[type[BaseProbe]] = [
    InjectionProbe,
    SSLProbe,
    HeadersProbe,
    RedirectProbe,
    ContentProbe,
]

# All probes including optional external API probes
ALL_PROBES: list[type[BaseProbe]] = [
    InjectionProbe,
    SSLProbe,
    HeadersProbe,
    RedirectProbe,
    ContentProbe,
    SafeBrowsingProbe,
    VirusTotalProbe,
]


def get_available_probes(
    include_safebrowsing: bool = True,
    include_virustotal: bool = True,
) -> list[type[BaseProbe]]:
    """Get list of probe classes that are available based on configuration.

    Args:
        include_safebrowsing: Include SafeBrowsingProbe if API key is available.
        include_virustotal: Include VirusTotalProbe if API key is available.

    Returns:
        List of probe classes that can be instantiated.
    """
    probes: list[type[BaseProbe]] = list(CORE_PROBES)

    if include_safebrowsing and os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY"):
        probes.append(SafeBrowsingProbe)

    if include_virustotal and os.environ.get("VIRUSTOTAL_API_KEY"):
        probes.append(VirusTotalProbe)

    return probes


def get_probe_availability() -> dict[str, bool]:
    """Check which optional probes are available.

    Returns:
        Dict mapping probe names to availability status.
    """
    return {
        "safebrowsing": bool(os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")),
        "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
    }


__all__ = [
    "BaseProbe",
    "ProbeInput",
    "InjectionProbe",
    "SSLProbe",
    "HeadersProbe",
    "RedirectProbe",
    "ContentProbe",
    "SafeBrowsingProbe",
    "VirusTotalProbe",
    "CORE_PROBES",
    "ALL_PROBES",
    "get_available_probes",
    "get_probe_availability",
]
