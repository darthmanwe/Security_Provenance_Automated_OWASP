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
                            "properties": {
                                "tags": ["CWE-95", "owasp-top-10:a03-injection"]
                            },
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
                                "region": {"startLine": 3, "endLine": 3},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}


class FixPlanTests(unittest.TestCase):
    def test_fix_plan_generates_evidence_bundle(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / "app.py").write_text(
                textwrap.dedent(
                    """
                    def run(user_input: str) -> str:
                        result = eval(user_input)
                        return result
                    """
                ).strip()
                + "\n",
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

            subprocess.run(
                [sys.executable, "-m", "spao", "init", "--project-name", "demo"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            subprocess.run(
                [sys.executable, "-m", "spao", "ingest"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            analyze_result = subprocess.run(
                [sys.executable, "-m", "spao", "analyze", "--sarif", str(fixture_path)],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            finding_id = json.loads(analyze_result.stdout)["summary"]["total"]
            self.assertEqual(finding_id, 1)
            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]

            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "plan", target],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            payload = json.loads(result.stdout)
            plan_data = json.loads(Path(payload["plan_path"]).read_text(encoding="utf-8"))
            self.assertEqual(plan_data["finding"]["id"], target)
            self.assertTrue(plan_data["line_window"])
            self.assertTrue(plan_data["recommended_actions"])


if __name__ == "__main__":
    unittest.main()
