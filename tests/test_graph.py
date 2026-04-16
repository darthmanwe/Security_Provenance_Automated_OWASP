from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import types
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from spao.config import SpaoConfig
from spao.fix.planner import build_fix_plan
from spao.graph.backends import persist_document
from spao.graph.store import save_findings, save_graph
from spao.models import GraphDocument, GraphEdge, GraphNode
from spao.sarif.models import Finding


class FakeNeo4jBackend:
    def __init__(self, uri: str, username: str, password: str) -> None:
        self.uri = uri
        self.username = username
        self.password = password
        self.persisted: GraphDocument | None = None

    def persist(self, document: GraphDocument):
        self.persisted = document
        return type(
            "Result",
            (),
            {"backend": "neo4j", "node_count": len(document.nodes), "edge_count": len(document.edges)},
        )()


class GraphCommandTests(unittest.TestCase):
    def test_graph_query_helpers_and_neo4j_persistence_contract(self) -> None:
        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
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
            subprocess.run(["git", "config", "user.email", "tests@example.com"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=repo, check=True, capture_output=True)

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(__file__).resolve().parent.parent)

            for command in (
                [sys.executable, "-m", "spao", "init", "--project-name", "demo"],
                [sys.executable, "-m", "spao", "ingest"],
            ):
                subprocess.run(
                    command,
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    env=env,
                    text=True,
                )

            symbols_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "spao",
                    "graph",
                    "query",
                    "--kind",
                    "symbols",
                    "--path",
                    "handler.ts",
                    "--line-start",
                    "1",
                ],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            symbols_payload = json.loads(symbols_result.stdout)
            symbol_names = {item["properties"]["name"] for item in symbols_payload["results"]}
            self.assertIn("handle", symbol_names)

            neighbors_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "spao",
                    "graph",
                    "query",
                    "--kind",
                    "neighbors",
                    "--path",
                    "handler.ts",
                    "--line-start",
                    "2",
                ],
                cwd=repo,
                check=True,
                capture_output=True,
                env=env,
                text=True,
            )
            neighbors_payload = json.loads(neighbors_result.stdout)
            self.assertEqual(neighbors_payload["results"]["file"]["properties"]["path"], "handler.ts")
            self.assertTrue(neighbors_payload["results"]["statements"])

            document = GraphDocument(
                metadata={"repo_name": "demo"},
                nodes=[GraphNode(node_id="node-1", label="File", properties={"path": "handler.ts"})],
                edges=[GraphEdge(edge_id="edge-1", edge_type="CONTAINS", source="node-1", target="node-1")],
            )
            config = SpaoConfig(project_name="demo", neo4j_password_env="TEST_NEO4J_PASSWORD")

            with patch("spao.graph.backends.Neo4jGraphBackend", FakeNeo4jBackend):
                with patch.dict(os.environ, {"TEST_NEO4J_PASSWORD": "secret"}, clear=False):
                    result = persist_document(document, config)

            self.assertEqual(result.backend, "neo4j")
            self.assertEqual(result.node_count, 1)
            self.assertEqual(result.edge_count, 1)

    def test_fix_plan_prefers_neo4j_retrieval_when_configured(self) -> None:
        class FakeResult:
            def __init__(self, rows: list[dict[str, object]]) -> None:
                self.rows = rows

            def __iter__(self):
                return iter(self.rows)

        class FakeSession:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def execute_read(self, func, *args):
                return func(self, *args)

            def run(self, query: str, **params):
                label = params.get("label")
                if "RETURN n.node_id AS node_id" in query:
                    if label == "File":
                        return FakeResult(
                            [{"node_id": "file-1", "label": "File", "properties": {"path": "app.py"}}]
                        )
                    if label == "Symbol":
                        return FakeResult(
                            [
                                {
                                    "node_id": "symbol-1",
                                    "label": "Symbol",
                                    "properties": {
                                        "file_path": "app.py",
                                        "name": "run",
                                        "line_start": 1,
                                        "line_end": 3,
                                    },
                                }
                            ]
                        )
                    if label == "Statement":
                        return FakeResult(
                            [
                                {
                                    "node_id": "stmt-1",
                                    "label": "Statement",
                                    "properties": {
                                        "file_path": "app.py",
                                        "line_start": 2,
                                        "line_end": 2,
                                        "kind": "Call",
                                    },
                                }
                            ]
                        )
                    if label == "LineSpan":
                        return FakeResult(
                            [
                                {
                                    "node_id": "line-2",
                                    "label": "LineSpan",
                                    "properties": {
                                        "file_path": "app.py",
                                        "line_start": 2,
                                        "line_end": 2,
                                    },
                                }
                            ]
                        )
                return FakeResult(
                    [
                        {
                            "edge_id": "edge-1",
                            "edge_type": "DECLARES",
                            "source": "file-1",
                            "target": "symbol-1",
                            "properties": {},
                        }
                    ]
                )

        class FakeDriver:
            def session(self):
                return FakeSession()

            def close(self):
                return None

        class FakeGraphDatabase:
            @staticmethod
            def driver(uri: str, auth: tuple[str, str]):
                return FakeDriver()

        with TemporaryDirectory() as tmp_dir:
            repo = Path(tmp_dir) / "demo"
            repo.mkdir()
            save_graph(
                repo,
                GraphDocument(
                    metadata={"repo_name": "demo"},
                    nodes=[GraphNode(node_id="json-file", label="File", properties={"path": "app.py"})],
                    edges=[],
                ),
            )
            save_findings(
                repo,
                [
                    Finding(
                        id="finding-1",
                        tool="semgrep",
                        rule_id="python.lang.security.audit.eval-detected.eval-detected",
                        title="eval detected",
                        message="Avoid eval().",
                        language="python",
                        file="app.py",
                        line_start=2,
                        line_end=2,
                        symbol="run",
                        severity="error",
                        confidence="high",
                        fingerprint="abc123",
                        cwe_refs=["CWE-95"],
                    )
                ],
                metadata={"summary": {"total": 1}},
            )
            config = SpaoConfig(project_name="demo", neo4j_password_env="TEST_NEO4J_PASSWORD")
            from spao.config import save_config

            save_config(repo, config)

            fake_module = types.SimpleNamespace(GraphDatabase=FakeGraphDatabase)
            with patch.dict(sys.modules, {"neo4j": fake_module}):
                with patch.dict(os.environ, {"TEST_NEO4J_PASSWORD": "secret"}, clear=False):
                    plan = build_fix_plan(repo, "finding-1")

            self.assertEqual(plan["retrieval_backend"], "neo4j")
            self.assertEqual(plan["symbol_nodes"][0]["properties"]["name"], "run")
            self.assertTrue(plan["neighbor_edges"])


if __name__ == "__main__":
    unittest.main()
