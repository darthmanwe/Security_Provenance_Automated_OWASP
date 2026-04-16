from __future__ import annotations

import os
from dataclasses import dataclass

from spao.config import SpaoConfig
from spao.models import GraphDocument


@dataclass(slots=True)
class PersistenceResult:
    backend: str
    node_count: int
    edge_count: int


class GraphBackend:
    def persist(self, document: GraphDocument) -> PersistenceResult:
        raise NotImplementedError


class Neo4jGraphBackend(GraphBackend):
    def __init__(self, uri: str, username: str, password: str) -> None:
        from neo4j import GraphDatabase

        self.driver = GraphDatabase.driver(uri, auth=(username, password))

    def persist(self, document: GraphDocument) -> PersistenceResult:
        with self.driver.session() as session:
            session.execute_write(self._persist_nodes, document.to_dict()["nodes"])
            session.execute_write(self._persist_edges, document.to_dict()["edges"])
        self.driver.close()
        return PersistenceResult(
            backend="neo4j",
            node_count=len(document.nodes),
            edge_count=len(document.edges),
        )

    @staticmethod
    def _persist_nodes(tx, nodes: list[dict[str, object]]) -> None:
        tx.run(
            """
            UNWIND $nodes AS node
            MERGE (n:GraphNode {node_id: node.node_id})
            SET n.label = node.label,
                n.properties = node.properties
            """,
            nodes=nodes,
        )

    @staticmethod
    def _persist_edges(tx, edges: list[dict[str, object]]) -> None:
        for edge in edges:
            relationship_type = _safe_relationship_type(str(edge["edge_type"]))
            tx.run(
                f"""
                MATCH (source:GraphNode {{node_id: $source}})
                MATCH (target:GraphNode {{node_id: $target}})
                MERGE (source)-[r:{relationship_type} {{edge_id: $edge_id}}]->(target)
                SET r.edge_type = $edge_type,
                    r.properties = $properties
                """,
                source=edge["source"],
                target=edge["target"],
                edge_id=edge["edge_id"],
                edge_type=edge["edge_type"],
                properties=edge.get("properties", {}),
            )


def persist_document(document: GraphDocument, config: SpaoConfig) -> PersistenceResult:
    password = os.environ.get(config.neo4j_password_env)
    if not password:
        raise RuntimeError(
            f"Neo4j persistence requested, but environment variable {config.neo4j_password_env} is not set."
        )
    backend = Neo4jGraphBackend(
        uri=config.neo4j_uri,
        username=config.neo4j_user,
        password=password,
    )
    return backend.persist(document)


def _safe_relationship_type(edge_type: str) -> str:
    cleaned = "".join(character if character.isalnum() or character == "_" else "_" for character in edge_type)
    if not cleaned:
        return "RELATED_TO"
    if cleaned[0].isdigit():
        cleaned = f"R_{cleaned}"
    return cleaned.upper()
