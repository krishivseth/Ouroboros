from __future__ import annotations

from .base import BaseRule
from .code_execution import CodeExecutionRule
from .command_injection import CommandInjectionRule
from .excessive_permissions import ExcessivePermissionsRule
from .indirect_prompt_injection import IndirectPromptInjectionRule
from .multi_vector import MultiVectorRule
from .prompt_injection import PromptInjectionRule
from .rug_pull import RugPullRule
from .token_leakage import TokenLeakageRule
from .tool_poisoning import ToolPoisoningRule
from .tool_shadowing import ToolShadowingRule

ALL_RULES: list[type[BaseRule]] = [
    PromptInjectionRule,
    ToolPoisoningRule,
    ExcessivePermissionsRule,
    RugPullRule,
    ToolShadowingRule,
    IndirectPromptInjectionRule,
    TokenLeakageRule,
    CodeExecutionRule,
    CommandInjectionRule,
]

__all__ = [
    "ALL_RULES",
    "BaseRule",
    "MultiVectorRule",
    "PromptInjectionRule",
    "ToolPoisoningRule",
    "ExcessivePermissionsRule",
    "RugPullRule",
    "ToolShadowingRule",
    "IndirectPromptInjectionRule",
    "TokenLeakageRule",
    "CodeExecutionRule",
    "CommandInjectionRule",
]
