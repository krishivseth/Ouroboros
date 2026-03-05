"""Integration tests against the Damn Vulnerable MCP Server challenge set.

Requires either:
  - DVMCP_PATH env var pointing to a local clone, or
  - network access to git-clone the repo into a temp directory.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from mcp_scanner.engine import scan
from mcp_scanner.models import RuleID, Severity

DVMCP_REPO = "https://github.com/harishsg993010/damn-vulnerable-MCP-server.git"

CHALLENGE_RULE_MAP: list[tuple[str, RuleID]] = [
    ("challenges/easy/challenge1", RuleID.PROMPT_INJECTION),
    ("challenges/easy/challenge2", RuleID.TOOL_POISONING),
    ("challenges/easy/challenge3", RuleID.EXCESSIVE_PERMISSIONS),
    ("challenges/medium/challenge4", RuleID.RUG_PULL),
    ("challenges/medium/challenge5", RuleID.TOOL_SHADOWING),
    ("challenges/medium/challenge6", RuleID.INDIRECT_PROMPT_INJECTION),
    ("challenges/medium/challenge7", RuleID.TOKEN_LEAKAGE),
    ("challenges/hard/challenge8", RuleID.CODE_EXECUTION),
    ("challenges/hard/challenge9", RuleID.COMMAND_INJECTION),
    ("challenges/hard/challenge10", RuleID.MULTI_VECTOR),
]


@pytest.fixture(scope="session")
def dvmcp_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    env_path = os.environ.get("DVMCP_PATH")
    if env_path:
        root = Path(env_path)
        if root.is_dir():
            return root

    clone_dir = tmp_path_factory.mktemp("dvmcp")
    subprocess.check_call(
        ["git", "clone", "--depth=1", DVMCP_REPO, str(clone_dir)],
        timeout=120,
    )
    return clone_dir


@pytest.mark.parametrize(
    "challenge_subdir,expected_rule_id",
    CHALLENGE_RULE_MAP,
    ids=[f"challenge{i+1}" for i in range(len(CHALLENGE_RULE_MAP))],
)
def test_challenge_fires_expected_rule(
    dvmcp_root: Path,
    challenge_subdir: str,
    expected_rule_id: RuleID,
) -> None:
    challenge_path = dvmcp_root / challenge_subdir
    assert challenge_path.is_dir(), f"Challenge dir not found: {challenge_path}"

    result = scan(str(challenge_path), min_severity=Severity.INFO)
    rule_ids_found = {f.rule_id for f in result.findings}

    assert expected_rule_id in rule_ids_found, (
        f"Expected {expected_rule_id.value} in findings for {challenge_subdir}, "
        f"but got: {[f.rule_id.value for f in result.findings]}"
    )


def test_full_scan_minimum_findings(dvmcp_root: Path) -> None:
    challenges_dir = dvmcp_root / "challenges"
    assert challenges_dir.is_dir(), f"challenges/ not found under {dvmcp_root}"

    result = scan(str(challenges_dir), min_severity=Severity.INFO)

    assert len(result.findings) >= 10, (
        f"Expected at least 10 findings across all challenges, got {len(result.findings)}"
    )
