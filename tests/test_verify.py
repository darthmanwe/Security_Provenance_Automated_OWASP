from __future__ import annotations

import json
import os
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
