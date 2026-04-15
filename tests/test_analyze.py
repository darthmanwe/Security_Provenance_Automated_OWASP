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
                                "region": {"startLine": 4, "endLine": 4},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}


class AnalyzeCommandTests(unittest.TestCase):
    def test_analyze_normalizes_sarif(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            (repo / "app.py").write_text("value = eval('1+1')\n", encoding="utf-8")
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
                text=True,
                env=env,
            )

            result = subprocess.run(
                [sys.executable, "-m", "spao", "analyze", "--sarif", str(fixture_path)],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            payload = json.loads(result.stdout)
            self.assertEqual(payload["summary"]["total"], 1)
            findings_path = repo / ".spao" / "findings.latest.json"
            findings_data = json.loads(findings_path.read_text(encoding="utf-8"))
            finding = findings_data["findings"][0]
            self.assertEqual(finding["tool"], "semgrep")
            self.assertEqual(finding["severity"], "high")
            self.assertIn("CWE-95", finding["cwe_refs"])
            self.assertIn("owasp-top10-2021:A03", finding["owasp_refs"])
            self.assertIn("asvs-5:V5", finding["asvs_refs"])
            self.assertIn("wstg:INPV", finding["wstg_refs"])
            self.assertTrue(finding["remediation_refs"])


if __name__ == "__main__":
    unittest.main()
