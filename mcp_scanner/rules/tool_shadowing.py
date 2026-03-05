from __future__ import annotations

from collections import Counter

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry
from .base import BaseRule


class ToolShadowingRule(BaseRule):
    rule_id = RuleID.TOOL_SHADOWING
    name = "Tool Shadowing"
    description = (
        "Detects duplicate tool names across FastMCP instances and "
        "tools whose descriptions reference other tools' resources."
    )
    severity = Severity.HIGH

    def analyze(self, registry: ServerRegistry) -> list[Finding]:
        findings: list[Finding] = []

        # Detection path 1: duplicate tool names
        name_counts: Counter[str] = Counter()
        name_to_entries: dict[str, list] = {}
        for tool in registry.tools:
            name_counts[tool.name] += 1
            name_to_entries.setdefault(tool.name, []).append(tool)

        for name, count in name_counts.items():
            if count < 2:
                continue
            entries = name_to_entries[name]
            for entry in entries:
                lineno = entry.line_number
                snippet = entry.source_lines[lineno - 1] if lineno <= len(entry.source_lines) else ""
                findings.append(Finding(
                    rule_id=self.rule_id,
                    severity=self.severity,
                    title=f"Duplicate tool name '{name}' ({count} definitions)",
                    description=(
                        f"Tool '{name}' is defined {count} times across the scanned "
                        f"files. A malicious server can shadow a legitimate tool by "
                        f"registering the same name."
                    ),
                    file_path=entry.file_path,
                    line_number=lineno,
                    snippet=snippet.rstrip(),
                    metadata={"function": name, "duplicate_count": count},
                ))

        # Detection path 2: docstring references another tool's name
        all_tool_names = {t.name for t in registry.tools}
        for tool in registry.tools:
            if not tool.docstring:
                continue
            doc_lower = tool.docstring.lower()
            for other_name in all_tool_names:
                if other_name == tool.name:
                    continue
                if other_name.lower() in doc_lower:
                    lineno = tool.line_number
                    snippet = tool.source_lines[lineno - 1] if lineno <= len(tool.source_lines) else ""
                    findings.append(Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        title=f"Tool '{tool.name}' docstring references tool '{other_name}'",
                        description=(
                            f"The docstring of tool '{tool.name}' mentions another "
                            f"registered tool '{other_name}', which may indicate "
                            f"cross-tool manipulation or shadowing intent."
                        ),
                        file_path=tool.file_path,
                        line_number=lineno,
                        snippet=snippet.rstrip(),
                        metadata={
                            "function": tool.name,
                            "referenced_tool": other_name,
                        },
                    ))

        return findings
