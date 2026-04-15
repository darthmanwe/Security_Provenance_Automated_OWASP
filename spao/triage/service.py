from __future__ import annotations

from collections import defaultdict

from spao.sarif.models import Finding


def summarize_findings(findings: list[Finding]) -> dict[str, object]:
    by_severity: dict[str, int] = defaultdict(int)
    by_tool: dict[str, int] = defaultdict(int)
    for finding in findings:
        by_severity[finding.severity] += 1
        by_tool[finding.tool] += 1
    return {
        "total": len(findings),
        "by_severity": dict(sorted(by_severity.items())),
        "by_tool": dict(sorted(by_tool.items())),
    }
