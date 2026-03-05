from __future__ import annotations

from collections import defaultdict

from ..models import Finding, RuleID, Severity
from ..registry import ServerRegistry


class MultiVectorRule:
    """Meta-rule that runs after all standard rules.

    Flags files where 3+ distinct RuleID values fired, indicating a
    compound multi-vector attack surface.
    """

    rule_id = RuleID.MULTI_VECTOR
    name = "Multi-Vector Compound Attack"
    severity = Severity.CRITICAL

    def analyze(
        self,
        registry: ServerRegistry,
        prior_findings: list[Finding],
    ) -> list[Finding]:
        by_file: dict[str, set[RuleID]] = defaultdict(set)
        for f in prior_findings:
            by_file[f.file_path].add(f.rule_id)

        findings: list[Finding] = []
        for file_path, rule_ids in by_file.items():
            if len(rule_ids) < 3:
                continue

            sorted_ids = sorted(rule_ids, key=lambda r: r.value)
            findings.append(Finding(
                rule_id=self.rule_id,
                severity=self.severity,
                title=f"Multi-vector attack surface in {file_path}",
                description=(
                    f"File '{file_path}' triggers {len(rule_ids)} distinct "
                    f"vulnerability classes: {', '.join(r.value for r in sorted_ids)}. "
                    f"These can be chained for a compound attack."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                metadata={
                    "distinct_rules": len(rule_ids),
                    "rule_ids": [r.value for r in sorted_ids],
                },
            ))

        return findings
