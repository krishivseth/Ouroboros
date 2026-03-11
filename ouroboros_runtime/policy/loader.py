"""Policy configuration loader."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from mcp_scanner.models import RuleID, Severity

logger = logging.getLogger(__name__)


class EnforcementAction(str, Enum):
    """Action to take when a rule fires."""
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    SKIP = "skip"


@dataclass
class RulePolicy:
    """Policy configuration for a single rule."""
    action: EnforcementAction = EnforcementAction.WARN
    severity_threshold: Severity | None = None


@dataclass
class DomainOverride:
    """Per-domain rule overrides."""
    domain: str
    rules: dict[str, EnforcementAction] = field(default_factory=dict)


@dataclass
class PolicySettings:
    """Global policy settings.
    
    NOTE: The `escalation` field is parsed from config but NOT IMPLEMENTED.
    All runtime detection is currently deterministic (regex-based).
    LLM-powered escalation for ambiguous findings is a planned feature.
    """
    # NOT IMPLEMENTED: Setting this to True has no effect. See README Known Limitations.
    escalation: bool = False
    cache_ttl_seconds: float = 300.0
    # NOT IMPLEMENTED: max_escalation_time_ms is unused since escalation is not implemented.
    max_escalation_time_ms: float = 3000.0
    max_cache_size: int = 1024


@dataclass
class PolicyConfig:
    """Complete policy configuration."""
    policies: dict[RuleID, RulePolicy] = field(default_factory=dict)
    allowlist: list[DomainOverride] = field(default_factory=list)
    settings: PolicySettings = field(default_factory=PolicySettings)


def _parse_action(value: str) -> EnforcementAction:
    """Parse action string to enum."""
    try:
        return EnforcementAction(value.lower())
    except ValueError:
        logger.warning("Unknown action '%s', defaulting to 'warn'", value)
        return EnforcementAction.WARN


def _parse_severity(value: str | None) -> Severity | None:
    """Parse severity string to enum."""
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        logger.warning("Unknown severity '%s', ignoring threshold", value)
        return None


def _parse_rule_id(name: str) -> RuleID | None:
    """Parse rule ID string to enum."""
    normalized = name.lower().replace("_", "-")
    for rule in RuleID:
        if rule.value == normalized:
            return rule
    logger.warning("Unknown rule ID '%s', skipping", name)
    return None


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """Load policy configuration from YAML file.

    If path is None, loads the built-in defaults.
    """
    if path is None:
        path = Path(__file__).parent / "defaults.yaml"
    else:
        path = Path(path)

    if not path.exists():
        logger.warning("Policy file not found: %s, using defaults", path)
        return _get_default_policy()

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as e:
        logger.error("Failed to parse policy file: %s", e)
        return _get_default_policy()

    return _parse_policy_data(data)


def _parse_policy_data(data: dict[str, Any]) -> PolicyConfig:
    """Parse raw YAML data into PolicyConfig."""
    config = PolicyConfig()

    # Parse policies
    policies_data = data.get("policies", {})
    for rule_name, rule_config in policies_data.items():
        rule_id = _parse_rule_id(rule_name)
        if rule_id is None:
            continue

        if isinstance(rule_config, dict):
            action = _parse_action(rule_config.get("action", "warn"))
            threshold = _parse_severity(rule_config.get("severity_threshold"))
            config.policies[rule_id] = RulePolicy(action=action, severity_threshold=threshold)
        elif isinstance(rule_config, str):
            config.policies[rule_id] = RulePolicy(action=_parse_action(rule_config))

    # Parse allowlist
    allowlist_data = data.get("allowlist", [])
    for entry in allowlist_data:
        if not isinstance(entry, dict):
            continue
        domain = entry.get("domain", "")
        rules = {}
        for rule_name, action in entry.get("rules", {}).items():
            rules[rule_name.lower().replace("_", "-")] = _parse_action(action)
        config.allowlist.append(DomainOverride(domain=domain, rules=rules))

    # Parse settings
    # NOTE: escalation is parsed but NOT IMPLEMENTED - see PolicySettings docstring
    settings_data = data.get("settings", {})
    config.settings = PolicySettings(
        escalation=settings_data.get("escalation", False),  # Default False since not implemented
        cache_ttl_seconds=float(settings_data.get("cache_ttl_seconds", 300)),
        max_escalation_time_ms=float(settings_data.get("max_escalation_time_ms", 3000)),
        max_cache_size=int(settings_data.get("max_cache_size", 1024)),
    )

    return config


def _get_default_policy() -> PolicyConfig:
    """Return hardcoded default policy."""
    return PolicyConfig(
        policies={
            RuleID.RESPONSE_INJECTION: RulePolicy(EnforcementAction.BLOCK, Severity.HIGH),
            RuleID.EXFILTRATION_SIGNAL: RulePolicy(EnforcementAction.BLOCK, Severity.MEDIUM),
            RuleID.REDIRECT_SPOOFING: RulePolicy(EnforcementAction.BLOCK, Severity.HIGH),
            RuleID.TLS_FAILURE: RulePolicy(EnforcementAction.BLOCK),
            RuleID.MALICIOUS_CONTENT: RulePolicy(EnforcementAction.WARN, Severity.MEDIUM),
            RuleID.HEADER_MISCONFIGURATION: RulePolicy(EnforcementAction.LOG),
            RuleID.SCHEMA_DRIFT: RulePolicy(EnforcementAction.WARN),
            RuleID.BEHAVIORAL_INCONSISTENCY: RulePolicy(EnforcementAction.WARN),
            RuleID.CROSS_TOOL_EXFILTRATION: RulePolicy(EnforcementAction.BLOCK),
            RuleID.MCP_PAYLOAD_INJECTION: RulePolicy(EnforcementAction.BLOCK, Severity.HIGH),
        },
        settings=PolicySettings(),
    )
