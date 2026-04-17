"""Generate embeddings for code graph nodes using sentence-transformers.

Each Symbol and Statement node gets a text representation built from its
properties (name, kind, content, file path, line range).  These texts are
encoded into dense vectors that capture semantic meaning, enabling
nearest-neighbor retrieval over the code graph.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from spao.models import GraphDocument, GraphNode


DEFAULT_MODEL = "all-MiniLM-L6-v2"


@dataclass(slots=True)
class NodeEmbedding:
    node_id: str
    label: str
    text: str
    vector: list[float]

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "label": self.label,
            "text": self.text,
            "vector": self.vector,
        }


def _node_text(node: GraphNode) -> str | None:
    """Build a natural-language text for embedding from a graph node."""
    props = node.properties
    if node.label == "Symbol":
        name = props.get("name", "")
        kind = props.get("kind", "symbol")
        file_path = props.get("file_path", "")
        line_start = props.get("line_start", "?")
        line_end = props.get("line_end", "?")
        return f"{kind} {name} in {file_path} lines {line_start}-{line_end}"

    if node.label == "Statement":
        content = props.get("preview", "") or props.get("content", "")
        kind = props.get("kind", "statement")
        file_path = props.get("file_path", "")
        line = props.get("line_start", "?")
        if not content:
            return None
        return f"{kind} at {file_path}:{line}: {content[:200]}"

    if node.label == "File":
        path = props.get("path", "")
        lang = props.get("language", "")
        return f"file {path} language {lang}"

    if node.label == "LineSpan":
        content = props.get("text", "") or props.get("content", "")
        file_path = props.get("file_path", "")
        line = props.get("line_start", "?")
        if not content or not content.strip():
            return None
        return f"{file_path}:{line}: {content.strip()[:200]}"

    return None


def embed_graph(document: GraphDocument, model_name: str | None = None) -> list[NodeEmbedding]:
    """Embed all eligible nodes in a graph document.

    Returns a list of NodeEmbedding with dense vectors.  Skips nodes that
    produce empty or None text representations.
    """
    from sentence_transformers import SentenceTransformer

    model_name = model_name or os.environ.get("EMBEDDING_MODEL", DEFAULT_MODEL)
    model = SentenceTransformer(model_name)

    texts: list[str] = []
    nodes: list[GraphNode] = []
    for node in document.nodes:
        text = _node_text(node)
        if text:
            texts.append(text)
            nodes.append(node)

    if not texts:
        return []

    vectors = model.encode(texts, show_progress_bar=False, normalize_embeddings=True)

    results: list[NodeEmbedding] = []
    for node, text, vector in zip(nodes, texts, vectors):
        results.append(
            NodeEmbedding(
                node_id=node.node_id,
                label=node.label,
                text=text,
                vector=vector.tolist(),
            )
        )
    return results
