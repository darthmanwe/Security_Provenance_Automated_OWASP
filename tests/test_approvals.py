from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


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
                            "properties": {"tags": ["CWE-95", "owasp-top-10:a03-injection"]},
                            "helpUri": "https://cheatsheetseries.owasp.org/",
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
                                "region": {"startLine": 2, "endLine": 2},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "python.lang.security.audit.eval-detected.eval-detected",
                    "level": "error",
                    "message": {"text": "Avoid eval()."},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "app.py"},
                                "region": {"startLine": 5, "endLine": 5},
                            }
                        }
                    ],
                },
            ],
        }
    ]
}


class ApprovalWorkflowTests(unittest.TestCase):
    def test_grouped_approvals_and_section_apply(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.py"
            app_path.write_text(
                textwrap.dedent(
                    """
                    def first(user_input: str) -> str:
                        return eval(user_input)

                    def second(user_input: str) -> str:
                        return eval(user_input)
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(SARIF_FIXTURE), encoding="utf-8")

            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True)

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

            for command in (
                [sys.executable, "-m", "spao", "init", "--project-name", "demo"],
                [sys.executable, "-m", "spao", "ingest"],
                [sys.executable, "-m", "spao", "analyze", "--sarif", str(fixture_path)],
            ):
                subprocess.run(
                    command,
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    env=env,
                    text=True,
                )

            findings_result = subprocess.run(
                [sys.executable, "-m", "spao", "findings", "list"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            findings_payload = json.loads(findings_result.stdout)
            section_id = findings_payload["findings"][0]["section_id"]
            self.assertEqual(
                findings_payload["findings"][0]["grouped_finding_ids"],
                findings_payload["findings"][1]["grouped_finding_ids"],
            )

            plan_result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "plan", findings_payload["findings"][0]["id"], "--group-by", "file"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            plan_payload = json.loads(plan_result.stdout)
            self.assertEqual(len(plan_payload["target_findings"]), 2)
            saved_plan = json.loads(Path(plan_payload["plan_path"]).read_text(encoding="utf-8"))
            self.assertTrue(saved_plan["multi_finding_sections"])

            blocked_apply = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", section_id, "--approve"],
                cwd=repo,
                check=False,
                capture_output=True,
                env=env,
                text=True,
            )
            self.assertNotEqual(blocked_apply.returncode, 0)
            self.assertIn("must be approved", blocked_apply.stdout)

            approvals_result = subprocess.run(
                [sys.executable, "-m", "spao", "approvals", "list"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            approvals_payload = json.loads(approvals_result.stdout)
            self.assertEqual(len(approvals_payload["sections"]), 1)

            subprocess.run(
                [sys.executable, "-m", "spao", "approvals", "approve", section_id],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            apply_result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", section_id, "--approve"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            apply_payload = json.loads(apply_result.stdout)
            self.assertEqual(len(apply_payload["applied_findings"]), 2)
            updated = app_path.read_text(encoding="utf-8")
            self.assertEqual(updated.count("literal_eval("), 2)

            findings_after = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            self.assertTrue(all(item["section_status"] == "applied" for item in findings_after["findings"]))


if __name__ == "__main__":
    unittest.main()
