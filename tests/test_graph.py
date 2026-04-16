from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from spao.config import SpaoConfig
from spao.graph.backends import persist_document
from spao.models import GraphDocument, GraphEdge, GraphNode


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


if __name__ == "__main__":
    unittest.main()
