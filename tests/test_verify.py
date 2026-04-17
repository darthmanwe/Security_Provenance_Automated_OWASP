from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from spao.gitops.push import record_push
from spao.gitops.service import GitResult
from spao.verify.service import discover_verification_command, run_verification


SARIF_FIXTURE = {
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {
                            "id": "python.lang.security.audit.eval-detected.eval-detected",
                            "name": "eval detected",
                            "properties": {"tags": ["CWE-95"]},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "python.lang.security.audit.eval-detected.eval-detected",
                    "level": "error",
                    "message": {"text": "Avoid eval()."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 1, "endLine": 1},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}


class VerifyCommandTests(unittest.TestCase):
    def test_discover_verification_command_uses_python_discovery_without_tests_dir(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / "test_smoke.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")

            with patch("spao.verify.service.shutil.which", return_value=None):
                verification = discover_verification_command(repo)

            self.assertIsNotNone(verification)
            self.assertEqual(verification.strategy, "unittest_discovery")
            self.assertEqual(verification.command, [sys.executable, "-m", "unittest", "discover", "-v"])

    def test_discover_verification_command_prefers_notebook_when_no_tests_dir(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / "main.ipynb").write_text("{}", encoding="utf-8")

            with patch("spao.verify.service.shutil.which") as which:
                which.side_effect = lambda name: "jupyter" if name == "jupyter" else None
                verification = discover_verification_command(repo)

            self.assertIsNotNone(verification)
            self.assertEqual(verification.strategy, "notebook_execute")
            self.assertEqual(verification.command[:5], ["jupyter", "nbconvert", "--to", "notebook", "--execute"])
            self.assertIn("main.verified.ipynb", verification.command)

    def test_verify_uses_notebook_fallback_when_no_tests_dir(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / "main.ipynb").write_text("{}", encoding="utf-8")
            (repo / ".spao").mkdir()
            (repo / ".spao" / "findings.latest.json").write_text(
                json.dumps({"metadata": {"summary": {"total": 0}}, "findings": []}, indent=2) + "\n",
                encoding="utf-8",
            )

            with patch("spao.verify.service.subprocess.run") as subprocess_run:
                subprocess_run.return_value = subprocess.CompletedProcess(
                    args=["jupyter", "nbconvert"],
                    returncode=0,
                    stdout="executed",
                    stderr="",
                )
                with patch("spao.verify.service.shutil.which") as which:
                    which.side_effect = lambda name: "jupyter" if name == "jupyter" else None
                    payload = run_verification(repo)

            self.assertTrue(payload["passed"])
            self.assertEqual(payload["strategy"], "notebook_execute")
            self.assertIn("jupyter nbconvert --to notebook --execute", payload["command"])
            self.assertEqual(
                subprocess_run.call_args.kwargs["env"]["JUPYTER_RUNTIME_DIR"],
                str(repo / ".spao" / "runtime"),
            )
            self.assertEqual(
                subprocess_run.call_args.kwargs["env"]["JUPYTER_ALLOW_INSECURE_WRITES"],
                "true",
            )

    def test_verify_reports_missing_strategy_when_repo_has_no_tests_or_notebooks(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / ".spao").mkdir()
            (repo / ".spao" / "findings.latest.json").write_text(
                json.dumps({"metadata": {"summary": {"total": 0}}, "findings": []}, indent=2) + "\n",
                encoding="utf-8",
            )

            payload = run_verification(repo)

            self.assertFalse(payload["passed"])
            self.assertEqual(payload["strategy"], "none")
            self.assertIn("No verification command discovered", payload["stderr"])

    def test_verify_updates_finding_state(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / "app.py").write_text("value = eval('1+1')\n", encoding="utf-8")
            (repo / "tests").mkdir()
            (repo / "tests" / "test_smoke.py").write_text(
                "import unittest\n\n\nclass Smoke(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(SARIF_FIXTURE), encoding="utf-8")

            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "config", "user.email", "tests@example.com"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test User"],
                cwd=repo,
                check=True,
                capture_output=True,
            )
            subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True)

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)
            for command in (
                [sys.executable, "-m", "spao", "init", "--project-name", "demo"],
                [sys.executable, "-m", "spao", "analyze", "--sarif", str(fixture_path)],
                [sys.executable, "-m", "spao", "verify"],
            ):
                subprocess.run(
                    command,
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                    env=env,
                )

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            self.assertEqual(findings["findings"][0]["verification_state"], "verification_passed")
            verify_payload = json.loads((repo / ".spao" / "verify.latest.json").read_text(encoding="utf-8"))
            self.assertTrue(verify_payload["passed"])
            self.assertIn("section_summary", verify_payload)

    def test_push_is_gated_until_applied_sections_are_verified(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / ".spao").mkdir()
            findings_payload = {
                "metadata": {"summary": {"total": 1}},
                "findings": [
                    {
                        "id": "finding-1",
                        "tool": "semgrep",
                        "rule_id": "python.lang.security.audit.eval-detected.eval-detected",
                        "title": "eval detected",
                        "message": "Avoid eval().",
                        "language": "python",
                        "file": "app.py",
                        "line_start": 1,
                        "line_end": 1,
                        "symbol": "run",
                        "severity": "error",
                        "confidence": "high",
                        "fingerprint": "abc123",
                        "cwe_refs": ["CWE-95"],
                        "owasp_refs": [],
                        "asvs_refs": [],
                        "wstg_refs": [],
                        "evidence_subgraph_id": None,
                        "remediation_refs": [],
                        "approval_state": "patch_applied",
                        "section_id": None,
                        "section_status": "pending",
                        "grouped_finding_ids": [],
                        "verification_state": "not_run",
                        "push_state": "not_pushed",
                    }
                ],
            }
            (repo / ".spao" / "findings.latest.json").write_text(
                json.dumps(findings_payload, indent=2) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "Push is gated"):
                record_push(repo)

    def test_push_marks_verified_sections_ready(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / ".spao").mkdir()
            findings_payload = {
                "metadata": {"summary": {"total": 1}},
                "findings": [
                    {
                        "id": "finding-1",
                        "tool": "semgrep",
                        "rule_id": "python.lang.security.audit.eval-detected.eval-detected",
                        "title": "eval detected",
                        "message": "Avoid eval().",
                        "language": "python",
                        "file": "app.py",
                        "line_start": 1,
                        "line_end": 1,
                        "symbol": "run",
                        "severity": "error",
                        "confidence": "high",
                        "fingerprint": "abc123",
                        "cwe_refs": ["CWE-95"],
                        "owasp_refs": [],
                        "asvs_refs": [],
                        "wstg_refs": [],
                        "evidence_subgraph_id": None,
                        "remediation_refs": [],
                        "approval_state": "verification_passed",
                        "section_id": None,
                        "section_status": "pending",
                        "grouped_finding_ids": [],
                        "verification_state": "verification_passed",
                        "push_state": "not_pushed",
                    }
                ],
            }
            (repo / ".spao" / "findings.latest.json").write_text(
                json.dumps(findings_payload, indent=2) + "\n",
                encoding="utf-8",
            )

            with patch("spao.gitops.push.push_current_branch") as push_current_branch:
                with patch("spao.gitops.push.current_branch", return_value="main"):
                    push_current_branch.return_value = GitResult(
                        command=["git", "push"],
                        returncode=0,
                        stdout="pushed",
                        stderr="",
                    )
                    payload = record_push(repo)

            self.assertEqual(payload["branch"], "main")
            self.assertIn("section_summary", payload)
            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            self.assertEqual(findings["findings"][0]["approval_state"], "ready_to_push")
            self.assertEqual(findings["findings"][0]["push_state"], "pushed")


if __name__ == "__main__":
    unittest.main()
