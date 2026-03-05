from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleID(str, Enum):
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
