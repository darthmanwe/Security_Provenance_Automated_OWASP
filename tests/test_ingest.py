from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class IngestCommandTests(unittest.TestCase):
    def test_ingest_builds_graph_artifact(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()

            (repo / "app.py").write_text(
                textwrap.dedent(
                    """
                    class Demo:
                        def run(self) -> str:
                            return "ok"
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (repo / "handler.js").write_text(
                textwrap.dedent(
                    """
                    export class Widget {
                        render() {
                            return "ok";
                        }
                    }

                    const format = (value) => value.trim();
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )
            (repo / "handler.ts").write_text(
                textwrap.dedent(
                    """
                    export function handle(): string {
                        return "ok";
                    }

                    const pick = (value: string) => value.toUpperCase();
                    """
                ).strip()
                + "\n",
                encoding="utf-8",
            )

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
            subprocess.run(
                ["git", "commit", "-m", "seed"],
                cwd=repo,
                check=True,
                capture_output=True,
            )

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

            init_result = subprocess.run(
                [sys.executable, "-m", "spao", "init", "--project-name", "demo"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertIn("Initialized", init_result.stdout)

            result = subprocess.run(
                [sys.executable, "-m", "spao", "ingest"],
                cwd=repo,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )

            payload = json.loads(result.stdout)
            graph_path = repo / ".spao" / "graph.latest.json"
            self.assertEqual(payload["graph_path"], str(graph_path))
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            labels = {node["label"] for node in graph["nodes"]}
            self.assertIn("File", labels)
            self.assertIn("LineSpan", labels)
            self.assertIn("Symbol", labels)
            self.assertGreaterEqual(graph["metadata"]["indexed_files"], 3)

            symbols = [
                node["properties"]
                for node in graph["nodes"]
                if node["label"] == "Symbol"
            ]
            js_class = next(
                symbol for symbol in symbols if symbol["file_path"] == "handler.js" and symbol["name"] == "Widget"
            )
            self.assertEqual(js_class["kind"], "class")
            self.assertTrue(js_class["is_exported"])

            js_method = next(
                symbol for symbol in symbols if symbol["file_path"] == "handler.js" and symbol["name"] == "render"
            )
            self.assertEqual(js_method["container_name"], "Widget")

            ts_arrow = next(
                symbol for symbol in symbols if symbol["file_path"] == "handler.ts" and symbol["name"] == "pick"
            )
            self.assertEqual(ts_arrow["kind"], "function")

            statements = [
                node["properties"]
                for node in graph["nodes"]
                if node["label"] == "Statement" and node["properties"]["file_path"] == "handler.ts"
            ]
            return_statement = next(
                statement for statement in statements if statement["kind"] == "ReturnStatement"
            )
            self.assertEqual(return_statement["container_name"], "handle")


if __name__ == "__main__":
    unittest.main()
