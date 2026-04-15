from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from spao.config import artifacts_dir
from spao.scanners.base import ScannerArtifact


def _run_command(command: list[str], cwd: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError:
        return 127, "binary-not-found"
    return completed.returncode, (completed.stdout or completed.stderr).strip()


def run_scanners(root: Path) -> list[ScannerArtifact]:
    output_dir = artifacts_dir(root)
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: list[ScannerArtifact] = []

    tools: list[tuple[str, list[str]]] = [
        (
            "semgrep",
            ["semgrep", "scan", "--config", "auto", "--sarif", "--output", str(output_dir / "semgrep.sarif"), "."],
        ),
        (
            "eslint",
            ["npx", "eslint", ".", "--format", "json"],
        ),
        (
            "ruff",
            ["ruff", "check", ".", "--output-format", "json"],
        ),
        (
            "bandit",
            ["bandit", "-r", ".", "-f", "json", "-o", str(output_dir / "bandit.json")],
        ),
    ]

    for tool, command in tools:
        binary = command[0]
        if shutil.which(binary) is None:
            artifacts.append(
                ScannerArtifact(tool=tool, path="", generated=False, status="unavailable")
            )
            continue

        returncode, _ = _run_command(command, root)
        artifacts.append(
            ScannerArtifact(
                tool=tool,
                path=str(output_dir / f"{tool}.sarif") if tool == "semgrep" else "",
                generated=returncode == 0 and tool == "semgrep",
                status="ok" if returncode == 0 else "failed",
            )
        )

    return artifacts
