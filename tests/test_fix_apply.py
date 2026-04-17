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
                                "region": {"startLine": 2, "endLine": 2},
                            }
                        }
                    ],
                }
            ],
        }
    ]
}


class FixApplyTests(unittest.TestCase):
    def test_fix_apply_rewrites_python_eval(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.py"
            app_path.write_text(
                textwrap.dedent(
                    """
                    def run(user_input: str) -> str:
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

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]
            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", target, "--approve"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            payload = json.loads(result.stdout)
            updated = app_path.read_text(encoding="utf-8")
            self.assertIn("literal_eval", updated)
            self.assertIn("from ast import literal_eval", updated)
            self.assertTrue(Path(payload["patch_path"]).exists())
            self.assertEqual(payload["remediation_family"], "python_eval_literal_eval")
            self.assertEqual(payload["applied_findings"], [target])

    def test_fix_apply_rewrites_js_eval_literal_payload(self) -> None:
        js_fixture = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "semgrep",
                            "rules": [
                                {
                                    "id": "javascript.lang.security.audit.eval-detected.eval-detected",
                                    "name": "eval detected",
                                    "properties": {"tags": ["CWE-95", "owasp-top-10:a03-injection"]},
                                    "helpUri": "https://cheatsheetseries.owasp.org/",
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "javascript.lang.security.audit.eval-detected.eval-detected",
                            "level": "error",
                            "message": {"text": "Avoid eval()."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.js"},
                                        "region": {"startLine": 2, "endLine": 2},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.js"
            app_path.write_text(
                textwrap.dedent(
                    """
                    export function run() {
                        return eval('{"answer": 42}')
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(js_fixture), encoding="utf-8")

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

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]
            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", target, "--approve"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            payload = json.loads(result.stdout)
            updated = app_path.read_text(encoding="utf-8")
            self.assertIn('JSON.parse("{\\"answer\\": 42}")', updated)
            self.assertEqual(payload["remediation_family"], "js_ts_dynamic_execution_literals")

    def test_fix_apply_rewrites_js_new_function_literal_payload(self) -> None:
        js_fixture = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "semgrep",
                            "rules": [
                                {
                                    "id": "javascript.lang.security.audit.new-function-detected.new-function-detected",
                                    "name": "new Function detected",
                                    "properties": {"tags": ["CWE-95", "owasp-top-10:a03-injection"]},
                                    "helpUri": "https://cheatsheetseries.owasp.org/",
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "javascript.lang.security.audit.new-function-detected.new-function-detected",
                            "level": "error",
                            "message": {"text": "Avoid new Function()."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.js"},
                                        "region": {"startLine": 2, "endLine": 2},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.js"
            app_path.write_text(
                textwrap.dedent(
                    """
                    export function run() {
                        return new Function('return {"answer": 42}')()
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(js_fixture), encoding="utf-8")

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

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]
            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", target, "--approve"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            payload = json.loads(result.stdout)
            updated = app_path.read_text(encoding="utf-8")
            self.assertIn('JSON.parse("{\\"answer\\": 42}")', updated)
            self.assertEqual(payload["remediation_family"], "js_ts_dynamic_execution_literals")

    def test_fix_apply_refuses_ambiguous_js_eval(self) -> None:
        js_fixture = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "semgrep",
                            "rules": [
                                {
                                    "id": "javascript.lang.security.audit.eval-detected.eval-detected",
                                    "name": "eval detected",
                                    "properties": {"tags": ["CWE-95", "owasp-top-10:a03-injection"]},
                                    "helpUri": "https://cheatsheetseries.owasp.org/",
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "javascript.lang.security.audit.eval-detected.eval-detected",
                            "level": "error",
                            "message": {"text": "Avoid eval()."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.js"},
                                        "region": {"startLine": 2, "endLine": 2},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.js"
            app_path.write_text(
                textwrap.dedent(
                    """
                    export function run(userInput) {
                        return eval(userInput)
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(js_fixture), encoding="utf-8")

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

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]
            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", target, "--approve"],
                cwd=repo,
                check=False,
                capture_output=True,
                env=env,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("No heuristic patch available", result.stdout)
            self.assertIn("eval(userInput)", app_path.read_text(encoding="utf-8"))

    def test_fix_apply_rewrites_python_yaml_load(self) -> None:
        yaml_fixture = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "semgrep",
                            "rules": [
                                {
                                    "id": "python.lang.security.audit.yaml-load.unsafe-load",
                                    "name": "unsafe yaml load",
                                    "properties": {"tags": ["CWE-502"]},
                                    "helpUri": "https://cheatsheetseries.owasp.org/",
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "python.lang.security.audit.yaml-load.unsafe-load",
                            "level": "error",
                            "message": {"text": "Avoid yaml.load()."},
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

        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.py"
            app_path.write_text(
                textwrap.dedent(
                    """
                    import yaml

                    def read_config(payload: str):
                        return yaml.load(payload)
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(yaml_fixture), encoding="utf-8")

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

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]
            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", target, "--approve"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            payload = json.loads(result.stdout)
            updated = app_path.read_text(encoding="utf-8")
            self.assertIn("yaml.safe_load(payload)", updated)
            self.assertEqual(payload["remediation_family"], "python_yaml_safe_load")

    def test_fix_apply_rewrites_ts_timer_string_callback(self) -> None:
        ts_fixture = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "semgrep",
                            "rules": [
                                {
                                    "id": "typescript.lang.security.audit.settimeout-string.settimeout-string",
                                    "name": "setTimeout string callback",
                                    "properties": {"tags": ["CWE-95"]},
                                    "helpUri": "https://cheatsheetseries.owasp.org/",
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "typescript.lang.security.audit.settimeout-string.settimeout-string",
                            "level": "error",
                            "message": {"text": "Avoid setTimeout string execution."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.ts"},
                                        "region": {"startLine": 6, "endLine": 6},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            app_path = repo / "app.ts"
            app_path.write_text(
                textwrap.dedent(
                    """
                    export function fire(): void {
                    }

                    export function schedule(): number {
                        return setTimeout("fire()", 1000)
                    }
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            fixture_path = repo / "fixture.sarif"
            fixture_path.write_text(json.dumps(ts_fixture), encoding="utf-8")

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

            findings = json.loads((repo / ".spao" / "findings.latest.json").read_text(encoding="utf-8"))
            target = findings["findings"][0]["id"]
            result = subprocess.run(
                [sys.executable, "-m", "spao", "fix", "apply", target, "--approve"],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )

            payload = json.loads(result.stdout)
            updated = app_path.read_text(encoding="utf-8")
            self.assertIn("setTimeout(() => fire(), 1000)", updated)
            self.assertEqual(payload["remediation_family"], "js_ts_timer_string_callback")


if __name__ == "__main__":
    unittest.main()
