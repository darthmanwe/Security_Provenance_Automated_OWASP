from __future__ import annotations

import json
from pathlib import Path

from spao.approval.state import assign_sections, require_push_ready, summarize_sections
from spao.gitops.service import current_branch, push_current_branch
from spao.graph.store import load_findings, save_findings


def push_state_path(root: Path) -> Path:
    directory = root / ".spao"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "push.latest.json"


def record_push(root: Path) -> dict[str, object]:
    metadata, findings = load_findings(root)
    findings = assign_sections(findings)
    require_push_ready(findings)

    result = push_current_branch(root)
    payload = {
        "branch": current_branch(root),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }

    updated = []
    for finding in findings:
        if finding.approval_state == "verification_passed":
            finding.approval_state = "ready_to_push"
            finding.push_state = "pushed"
        updated.append(finding)
    updated = assign_sections(updated)
    payload["section_summary"] = summarize_sections(updated)
    push_state_path(root).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    save_findings(root, updated, metadata)
    return payload
