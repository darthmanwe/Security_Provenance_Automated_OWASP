from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class GraphNode:
    node_id: str
    label: str
    properties: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class GraphEdge:
    edge_id: str
    edge_type: str
    source: str
    target: str
    properties: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class GraphDocument:
    metadata: dict[str, object]
    nodes: list[GraphNode]
    edges: list[GraphEdge]

    def to_dict(self) -> dict[str, object]:
        return {
            "metadata": self.metadata,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
        }
