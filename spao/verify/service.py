from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from spao.approval.state import assign_sections, summarize_sections
from spao.graph.store import load_findings, save_findings


@dataclass(slots=True)
class VerificationCommand:
    command: list[str]
    display: str
    strategy: str


def verify_path(root: Path) -> Path:
    directory = root / ".spao"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "verify.latest.json"


def _verification_artifacts_dir(root: Path) -> Path:
    directory = root / ".spao" / "artifacts"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _verification_runtime_dir(root: Path) -> Path:
    directory = root / ".spao" / "runtime"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _python_test_files(root: Path) -> list[Path]:
    return sorted(
        {
            *root.rglob("test_*.py"),
            *root.rglob("*_test.py"),
        }
    )


def _has_non_placeholder_npm_test(root: Path) -> bool:
    package_json = root / "package.json"
    if not package_json.exists():
        return False
    try:
        payload = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False
    scripts = payload.get("scripts", {})
    test_script = str(scripts.get("test", "")).strip()
    if not test_script:
        return False
    lowered = test_script.lower()
    return "no test specified" not in lowered


def _has_pytest_config(root: Path) -> bool:
    if (root / "pytest.ini").exists():
        return True
    if (root / "tox.ini").exists() and "[pytest]" in (root / "tox.ini").read_text(encoding="utf-8", errors="ignore"):
        return True
    if (root / "setup.cfg").exists() and "[tool:pytest]" in (root / "setup.cfg").read_text(encoding="utf-8", errors="ignore"):
        return True
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return False
    try:
        payload = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return False
    return "pytest" in payload.get("tool", {})


def discover_verification_command(root: Path) -> VerificationCommand | None:
    tests_dir = root / "tests"
    if tests_dir.exists() and tests_dir.is_dir():
        return VerificationCommand(
            command=[sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            display="python -m unittest discover -s tests -v",
            strategy="unittest_tests_dir",
        )

    if _has_non_placeholder_npm_test(root) and shutil.which("npm"):
        return VerificationCommand(
            command=["npm", "test"],
            display="npm test",
            strategy="npm_test_script",
        )

    python_test_files = _python_test_files(root)
    if python_test_files:
        if _has_pytest_config(root) or shutil.which("pytest"):
            return VerificationCommand(
                command=[sys.executable, "-m", "pytest", "-q"],
                display="python -m pytest -q",
                strategy="pytest_discovery",
            )
        return VerificationCommand(
            command=[sys.executable, "-m", "unittest", "discover", "-v"],
            display="python -m unittest discover -v",
            strategy="unittest_discovery",
        )

    notebooks = sorted(root.glob("*.ipynb"))
    if notebooks and shutil.which("jupyter"):
        preferred = next((item for item in notebooks if item.name.lower() == "main.ipynb"), notebooks[0])
        artifacts_dir = _verification_artifacts_dir(root)
        output_name = f"{preferred.stem}.verified.ipynb"
        return VerificationCommand(
            command=[
                "jupyter",
                "nbconvert",
                "--to",
                "notebook",
                "--execute",
                preferred.name,
                "--output",
                output_name,
                "--output-dir",
                str(artifacts_dir),
            ],
            display=(
                f"jupyter nbconvert --to notebook --execute {preferred.name} "
                f"--output {output_name} --output-dir {artifacts_dir}"
            ),
            strategy="notebook_execute",
        )

    return None


def run_verification(root: Path) -> dict[str, object]:
    verification = discover_verification_command(root)
    if verification is None:
        summary = {
            "command": None,
            "strategy": "none",
            "returncode": 5,
            "passed": False,
            "stdout": "",
            "stderr": "No verification command discovered for this repository.",
        }
        metadata, findings = load_findings(root)
        updated = []
        for finding in findings:
            finding.verification_state = "verification_failed"
            updated.append(finding)
        updated = assign_sections(updated)
        save_findings(root, updated, metadata)
        summary["section_summary"] = summarize_sections(updated)
        verify_path(root).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        return summary

    env = dict(os.environ)
    if verification.strategy == "notebook_execute":
        runtime_dir = _verification_runtime_dir(root)
        env["JUPYTER_RUNTIME_DIR"] = str(runtime_dir)
        env["JUPYTER_ALLOW_INSECURE_WRITES"] = "true"

    completed = subprocess.run(
        verification.command,
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    summary = {
        "command": verification.display,
        "strategy": verification.strategy,
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
