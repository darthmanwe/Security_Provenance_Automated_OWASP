from __future__ import annotations

import json
from pathlib import Path

from spao.models import GraphDocument
from spao.sarif.models import Finding


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


def findings_path(root: Path) -> Path:
    return ensure_runtime_dirs(root) / "findings.latest.json"


def save_findings(root: Path, findings: list[Finding], metadata: dict[str, object]) -> Path:
    payload = {
        "metadata": metadata,
        "findings": [finding.to_dict() for finding in findings],
    }
    target = findings_path(root)
    target.write_text(
        json.dumps(payload, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return target


def load_findings(root: Path) -> tuple[dict[str, object], list[Finding]]:
    data = json.loads(findings_path(root).read_text(encoding="utf-8"))
    return data["metadata"], [Finding(**finding) for finding in data["findings"]]
