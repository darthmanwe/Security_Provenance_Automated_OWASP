from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class InitCommandTests(unittest.TestCase):
    def test_init_creates_config(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()

            subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
            subprocess.run(
                ["git", "checkout", "-b", "test-branch"],
                cwd=repo,
                check=True,
                capture_output=True,
            )

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

            result = subprocess.run(
                [sys.executable, "-m", "spao", "init", "--project-name", "demo"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            payload = json.loads(result.stdout)
            config_path = repo / ".spao" / "config.json"
            self.assertEqual(payload["config_path"], str(config_path))
            self.assertEqual(payload["branch"], "test-branch")
            self.assertEqual(
                json.loads(config_path.read_text(encoding="utf-8"))["project_name"], "demo"
            )


if __name__ == "__main__":
    unittest.main()
