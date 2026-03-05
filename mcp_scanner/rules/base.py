from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry


class BaseRule(ABC):
    """Abstract base for all standard (non-meta) detection rules."""

    rule_id: RuleID
    name: str
    description: str
    severity: Severity

    @abstractmethod
    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        ...
