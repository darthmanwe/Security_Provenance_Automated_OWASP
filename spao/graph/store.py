from __future__ import annotations

import json
from pathlib import Path

from spao.models import GraphDocument


def ensure_runtime_dirs(root: Path) -> Path:
    runtime_dir = root / ".spao"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    return runtime_dir


def graph_path(root: Path) -> Path:
    return ensure_runtime_dirs(root) / "graph.latest.json"


def save_graph(root: Path, document: GraphDocument) -> Path:
    target = graph_path(root)
    target.write_text(
        json.dumps(document.to_dict(), indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return target


def load_graph(root: Path) -> GraphDocument:
    from spao.models import GraphEdge, GraphNode

    data = json.loads(graph_path(root).read_text(encoding="utf-8"))
    return GraphDocument(
        metadata=data["metadata"],
        nodes=[GraphNode(**node) for node in data["nodes"]],
        edges=[GraphEdge(**edge) for edge in data["edges"]],
    )
