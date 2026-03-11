"""Schema drift detection for MCP tool responses."""
from __future__ import annotations

import json
import logging
from typing import Any

from mcp_scanner.models import RuleID, Severity, RuntimeFinding

logger = logging.getLogger(__name__)


class SchemaDriftProbe:
    """Detects when MCP tool responses diverge from declared schemas.

    Schema drift can indicate:
    - Rug-pull attacks where behavior changes after initial trust
    - Buggy implementations that may have security implications
    - Malicious servers returning unexpected data structures
    """

    def check(
        self,
        declared_schema: dict[str, Any],
        actual_response: dict[str, Any],
        tool_name: str,
    ) -> RuntimeFinding | None:
        """Compare response structure to declared schema.

        Args:
            declared_schema: The JSON schema declared by the tool.
            actual_response: The actual response from the tool.
            tool_name: Name of the tool being checked.

        Returns:
            RuntimeFinding if drift detected, None otherwise.
        """
        if not declared_schema:
            return None

        drift_issues = self._find_drift(declared_schema, actual_response, "root")

        if drift_issues:
            return RuntimeFinding(
                rule_id=RuleID.SANDBOX_SCHEMA_DRIFT,
                severity=Severity.MEDIUM,
                title=f"Schema drift detected in tool '{tool_name}'",
                description=(
                    f"The response from '{tool_name}' does not match its declared schema. "
                    f"Found {len(drift_issues)} discrepancies."
                ),
                target=tool_name,
                evidence="\n".join(drift_issues[:5]),
                metadata={
                    "tool_name": tool_name,
                    "drift_count": len(drift_issues),
                    "all_issues": drift_issues,
                },
            )

        return None

    def _find_drift(
        self,
        schema: dict[str, Any],
        value: Any,
        path: str,
    ) -> list[str]:
        """Recursively find schema drift issues.

        Args:
            schema: JSON schema to validate against.
            value: Actual value to check.
            path: Current path in the object for error messages.

        Returns:
            List of drift issue descriptions.
        """
        issues = []

        schema_type = schema.get("type")

        if schema_type == "object":
            if not isinstance(value, dict):
                issues.append(f"{path}: expected object, got {type(value).__name__}")
                return issues

            properties = schema.get("properties", {})
            required = schema.get("required", [])

            for req_prop in required:
                if req_prop not in value:
                    issues.append(f"{path}.{req_prop}: required property missing")

            additional = schema.get("additionalProperties", True)
            if additional is False:
                for key in value:
                    if key not in properties:
                        issues.append(f"{path}.{key}: unexpected property")

            for prop_name, prop_schema in properties.items():
                if prop_name in value:
                    sub_issues = self._find_drift(
                        prop_schema,
                        value[prop_name],
                        f"{path}.{prop_name}",
                    )
                    issues.extend(sub_issues)

        elif schema_type == "array":
            if not isinstance(value, list):
                issues.append(f"{path}: expected array, got {type(value).__name__}")
                return issues

            items_schema = schema.get("items", {})
            for i, item in enumerate(value[:10]):
                sub_issues = self._find_drift(items_schema, item, f"{path}[{i}]")
                issues.extend(sub_issues)

        elif schema_type == "string":
            if not isinstance(value, str):
                issues.append(f"{path}: expected string, got {type(value).__name__}")

        elif schema_type == "number":
            if not isinstance(value, (int, float)):
                issues.append(f"{path}: expected number, got {type(value).__name__}")

        elif schema_type == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                issues.append(f"{path}: expected integer, got {type(value).__name__}")

        elif schema_type == "boolean":
            if not isinstance(value, bool):
                issues.append(f"{path}: expected boolean, got {type(value).__name__}")

        elif schema_type == "null":
            if value is not None:
                issues.append(f"{path}: expected null, got {type(value).__name__}")

        return issues

    def check_for_suspicious_fields(
        self,
        response: dict[str, Any],
        tool_name: str,
    ) -> RuntimeFinding | None:
        """Check for suspicious fields in the response regardless of schema.

        Args:
            response: The tool response to check.
            tool_name: Name of the tool.

        Returns:
            RuntimeFinding if suspicious fields found.
        """
        suspicious_keys = {
            "system", "prompt", "instruction", "command", "execute",
            "eval", "exec", "shell", "code", "script", "hidden",
            "__proto__", "constructor", "prototype",
        }

        found_suspicious = []

        def check_keys(obj: Any, path: str = "root") -> None:
            if isinstance(obj, dict):
                for key, val in obj.items():
                    key_lower = key.lower()
                    if key_lower in suspicious_keys:
                        found_suspicious.append(f"{path}.{key}")
                    check_keys(val, f"{path}.{key}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj[:20]):
                    check_keys(item, f"{path}[{i}]")

        check_keys(response)

        if found_suspicious:
            return RuntimeFinding(
                rule_id=RuleID.SANDBOX_SCHEMA_DRIFT,
                severity=Severity.HIGH,
                title=f"Suspicious fields in '{tool_name}' response",
                description=(
                    f"The response contains fields with suspicious names that may indicate "
                    f"an attempt to inject instructions or execute code."
                ),
                target=tool_name,
                evidence=f"Suspicious fields: {', '.join(found_suspicious[:10])}",
                metadata={
                    "tool_name": tool_name,
                    "suspicious_fields": found_suspicious,
                },
            )

        return None
