"""GraphRAG retrieval: embedding-based nearest-neighbor search over the code graph.

Given a finding, this module builds a query embedding from the finding's context
(file, rule, CWE, line range, message) and retrieves the most semantically
relevant graph nodes.  The results augment the deterministic graph traversal
that the fix planner already performs.
"""

from __future__ import annotations

import os
from pathlib import Path

from spao.graphrag.embeddings import DEFAULT_MODEL, NodeEmbedding
from spao.graphrag.store import load_embeddings, search_similar
from spao.sarif.models import Finding


def _build_finding_query_text(finding: Finding) -> str:
    """Build a natural-language query from a finding for embedding."""
    parts = [
        f"security finding in {finding.file}",
        f"lines {finding.line_start}-{finding.line_end}",
        f"rule {finding.rule_id}",
    ]
    if finding.cwe_refs:
        parts.append(f"CWE {', '.join(finding.cwe_refs)}")
    if finding.message:
        parts.append(finding.message[:200])
    return " ".join(parts)


def retrieve_graphrag_context(
    root: Path,
    finding: Finding,
    top_k: int = 20,
) -> dict[str, object] | None:
    """Retrieve graph context using embedding similarity.

    Returns a dict matching the shape expected by the fix planner, or None
    if embeddings are not available.
    """
    if not (root / ".spao" / "embeddings.json").exists():
        return None

    try:
        from sentence_transformers import SentenceTransformer
    except ImportError:
        return None

    embeddings = load_embeddings(root)
    if not embeddings:
        return None

    model_name = os.environ.get("EMBEDDING_MODEL", DEFAULT_MODEL)
    model = SentenceTransformer(model_name)
    query_text = _build_finding_query_text(finding)
    query_vector = model.encode([query_text], normalize_embeddings=True)[0].tolist()

    symbol_results = search_similar(query_vector, embeddings, top_k=top_k, label_filter="Symbol")
    statement_results = search_similar(query_vector, embeddings, top_k=top_k, label_filter="Statement")
    file_results = search_similar(query_vector, embeddings, top_k=5, label_filter="File")
    line_results = search_similar(query_vector, embeddings, top_k=top_k, label_filter="LineSpan")

    def _to_node_dict(emb: NodeEmbedding, score: float) -> dict:
        return {
            "node_id": emb.node_id,
            "label": emb.label,
            "text": emb.text,
            "similarity": round(score, 4),
        }

    return {
        "backend": "graphrag",
        "query_text": query_text,
        "file_nodes": [_to_node_dict(e, s) for e, s in file_results],
        "symbol_nodes": [_to_node_dict(e, s) for e, s in symbol_results],
        "statement_nodes": [_to_node_dict(e, s) for e, s in statement_results],
        "line_window": [_to_node_dict(e, s) for e, s in line_results],
        "neighbor_edges": [],
    }
