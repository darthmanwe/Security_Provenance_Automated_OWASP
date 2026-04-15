from __future__ import annotations

import json
from pathlib import Path

from spao.gitops.service import current_branch, push_current_branch
from spao.graph.store import load_findings, save_findings


def push_state_path(root: Path) -> Path:
    directory = root / ".spao"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "push.latest.json"


def record_push(root: Path) -> dict[str, object]:
    result = push_current_branch(root)
    payload = {
        "branch": current_branch(root),
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode,
    }
    push_state_path(root).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    metadata, findings = load_findings(root)
    updated = []
    for finding in findings:
        finding.push_state = "pushed"
        updated.append(finding)
    save_findings(root, updated, metadata)
    return payload
