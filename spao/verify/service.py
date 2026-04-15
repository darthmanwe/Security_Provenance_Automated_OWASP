from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

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
    verify_path(root).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    metadata, findings = load_findings(root)
    updated = []
    for finding in findings:
        finding.verification_state = (
            "verification_passed" if completed.returncode == 0 else "verification_failed"
        )
        updated.append(finding)
    save_findings(root, updated, metadata)
    return summary
