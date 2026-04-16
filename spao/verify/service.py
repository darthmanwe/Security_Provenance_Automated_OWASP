from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from spao.approval.state import assign_sections, summarize_sections
from spao.graph.store import load_findings, save_findings


def verify_path(root: Path) -> Path:
    directory = root / ".spao"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "verify.latest.json"


def run_verification(root: Path) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    summary = {
        "command": "python -m unittest discover -s tests -v",
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }

    metadata, findings = load_findings(root)
    updated = []
    for finding in findings:
        finding.verification_state = (
            "verification_passed" if completed.returncode == 0 else "verification_failed"
        )
        if finding.approval_state == "patch_applied" and completed.returncode == 0:
            finding.approval_state = "verification_passed"
        updated.append(finding)
    updated = assign_sections(updated)
    save_findings(root, updated, metadata)
    summary["section_summary"] = summarize_sections(updated)
    verify_path(root).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary
