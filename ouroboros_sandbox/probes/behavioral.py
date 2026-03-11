"""Behavioral consistency probe for MCP tools."""
from __future__ import annotations

import hashlib
import json
import logging
from difflib import unified_diff
from typing import Any

from mcp_scanner.models import RuleID, Severity, RuntimeFinding

logger = logging.getLogger(__name__)


class BehavioralProbe:
    """Detects behavioral inconsistency in MCP tool responses.

    Behavioral inconsistency can indicate:
    - Dynamic payload delivery (different responses for same input)
    - Conditional exploitation based on timing or state
    - Rug-pull attacks where behavior changes over time
    """

    def __init__(self):
        self._response_cache: dict[str, list[dict[str, Any]]] = {}

    def record_response(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        response: dict[str, Any],
    ) -> None:
        """Record a tool response for later comparison.

        Args:
            tool_name: Name of the tool.
            arguments: Arguments passed to the tool.
            response: Response from the tool.
        """
        cache_key = self._make_cache_key(tool_name, arguments)

        if cache_key not in self._response_cache:
            self._response_cache[cache_key] = []

        self._response_cache[cache_key].append({
            "response": response,
            "hash": self._hash_response(response),
        })

    def check_consistency(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        responses: list[dict[str, Any]] | None = None,
    ) -> RuntimeFinding | None:
        """Check if multiple calls with same input return consistent output.

        Args:
            tool_name: Name of the tool.
            arguments: Arguments used for the calls.
            responses: List of responses to compare. If None, uses cached responses.

        Returns:
            RuntimeFinding if inconsistency detected, None otherwise.
        """
        if responses is None:
            cache_key = self._make_cache_key(tool_name, arguments)
            cached = self._response_cache.get(cache_key, [])
            responses = [r["response"] for r in cached]

        if len(responses) < 2:
            return None

        hashes = [self._hash_response(r) for r in responses]
        unique_hashes = set(hashes)

        if len(unique_hashes) == 1:
            return None

        diff_details = self._compute_diff(responses[0], responses[-1])

        return RuntimeFinding(
            rule_id=RuleID.SANDBOX_BEHAVIORAL_INCONSISTENCY,
            severity=Severity.HIGH,
            title=f"Behavioral inconsistency in tool '{tool_name}'",
            description=(
                f"The tool '{tool_name}' returned different responses for identical inputs. "
                f"Found {len(unique_hashes)} unique responses across {len(responses)} calls. "
                f"This may indicate dynamic payload delivery or conditional exploitation."
            ),
            target=tool_name,
            evidence=diff_details,
            metadata={
                "tool_name": tool_name,
                "arguments": arguments,
                "unique_responses": len(unique_hashes),
                "total_calls": len(responses),
                "response_hashes": hashes,
            },
        )

    def check_response_mutation(
        self,
        tool_name: str,
        response1: dict[str, Any],
        response2: dict[str, Any],
    ) -> RuntimeFinding | None:
        """Check if two responses show signs of mutation.

        Args:
            tool_name: Name of the tool.
            response1: First response.
            response2: Second response.

        Returns:
            RuntimeFinding if mutation detected.
        """
        hash1 = self._hash_response(response1)
        hash2 = self._hash_response(response2)

        if hash1 == hash2:
            return None

        structural_diff = self._find_structural_changes(response1, response2)

        if structural_diff:
            return RuntimeFinding(
                rule_id=RuleID.SANDBOX_BEHAVIORAL_INCONSISTENCY,
                severity=Severity.HIGH,
                title=f"Response mutation detected in '{tool_name}'",
                description=(
                    f"The tool's response structure changed between calls. "
                    f"This is a strong indicator of malicious behavior."
                ),
                target=tool_name,
                evidence="\n".join(structural_diff[:10]),
                metadata={
                    "tool_name": tool_name,
                    "structural_changes": structural_diff,
                },
            )

        return None

    def _make_cache_key(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """Create a cache key from tool name and arguments."""
        args_json = json.dumps(arguments, sort_keys=True, default=str)
        return f"{tool_name}:{hashlib.sha256(args_json.encode()).hexdigest()[:16]}"

    def _hash_response(self, response: dict[str, Any]) -> str:
        """Create a hash of a response for comparison."""
        normalized = json.dumps(response, sort_keys=True, default=str)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    def _compute_diff(
        self,
        response1: dict[str, Any],
        response2: dict[str, Any],
    ) -> str:
        """Compute a human-readable diff between two responses."""
        json1 = json.dumps(response1, indent=2, sort_keys=True, default=str)
        json2 = json.dumps(response2, indent=2, sort_keys=True, default=str)

        diff_lines = list(unified_diff(
            json1.splitlines(),
            json2.splitlines(),
            fromfile="response_1",
            tofile="response_2",
            lineterm="",
        ))

        return "\n".join(diff_lines[:50])

    def _find_structural_changes(
        self,
        obj1: Any,
        obj2: Any,
        path: str = "root",
    ) -> list[str]:
        """Find structural differences between two objects."""
        changes = []

        if type(obj1) != type(obj2):
            changes.append(f"{path}: type changed from {type(obj1).__name__} to {type(obj2).__name__}")
            return changes

        if isinstance(obj1, dict):
            keys1 = set(obj1.keys())
            keys2 = set(obj2.keys())

            for key in keys1 - keys2:
                changes.append(f"{path}.{key}: removed")
            for key in keys2 - keys1:
                changes.append(f"{path}.{key}: added")

            for key in keys1 & keys2:
                sub_changes = self._find_structural_changes(
                    obj1[key], obj2[key], f"{path}.{key}"
                )
                changes.extend(sub_changes)

        elif isinstance(obj1, list):
            if len(obj1) != len(obj2):
                changes.append(f"{path}: array length changed from {len(obj1)} to {len(obj2)}")

        return changes

    def clear_cache(self) -> None:
        """Clear the response cache."""
        self._response_cache.clear()
