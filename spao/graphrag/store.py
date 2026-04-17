"""Persist and load GraphRAG embeddings.

Embeddings are stored in .spao/embeddings.json alongside the graph artifact.
When Neo4j is available, embeddings can also be pushed to a Neo4j vector index
for server-side approximate nearest-neighbor search.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path

from spao.config import config_path, load_config
from spao.graphrag.embeddings import NodeEmbedding


def embeddings_path(root: Path) -> Path:
    directory = root / ".spao"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "embeddings.json"


def save_embeddings(root: Path, embeddings: list[NodeEmbedding]) -> Path:
    target = embeddings_path(root)
    payload = {
        "count": len(embeddings),
        "dimension": len(embeddings[0].vector) if embeddings else 0,
        "embeddings": [e.to_dict() for e in embeddings],
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def load_embeddings(root: Path) -> list[NodeEmbedding]:
    data = json.loads(embeddings_path(root).read_text(encoding="utf-8"))
    return [
        NodeEmbedding(
            node_id=e["node_id"],
            label=e["label"],
            text=e["text"],
            vector=e["vector"],
        )
        for e in data["embeddings"]
    ]


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def search_similar(
    query_vector: list[float],
    embeddings: list[NodeEmbedding],
    top_k: int = 20,
    label_filter: str | None = None,
) -> list[tuple[NodeEmbedding, float]]:
    """Find the top-k most similar embeddings to a query vector.

    Pure Python cosine similarity -- no external vector DB required.
    """
    scored: list[tuple[NodeEmbedding, float]] = []
    for emb in embeddings:
        if label_filter and emb.label != label_filter:
            continue
        sim = _cosine_similarity(query_vector, emb.vector)
        scored.append((emb, sim))
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return scored[:top_k]


def persist_embeddings_to_neo4j(root: Path, embeddings: list[NodeEmbedding]) -> int:
    """Push embedding vectors to Neo4j as node properties and create a vector index.

    Returns the number of nodes updated.  Silently returns 0 if Neo4j is
    unreachable or the driver is not installed.
    """
    if not config_path(root).exists():
        return 0
    config = load_config(root)
    password = os.environ.get(config.neo4j_password_env)
    if not password:
        return 0
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return 0

    if not embeddings:
        return 0

    dimension = len(embeddings[0].vector)
    driver = GraphDatabase.driver(config.neo4j_uri, auth=(config.neo4j_user, password))
    try:
        with driver.session() as session:
            session.run(
                "CREATE VECTOR INDEX spao_embedding IF NOT EXISTS "
                "FOR (n:GraphNode) ON (n.embedding) "
                "OPTIONS {indexConfig: {"
                f"  `vector.dimensions`: {dimension},"
                "  `vector.similarity_function`: 'cosine'"
                "}}"
            )
            for emb in embeddings:
                session.run(
                    "MATCH (n:GraphNode {node_id: $node_id}) "
                    "SET n.embedding = $vector, n.embedding_text = $text",
                    node_id=emb.node_id,
                    vector=emb.vector,
                    text=emb.text,
                )
    except Exception:
        return 0
    finally:
        driver.close()
    return len(embeddings)
