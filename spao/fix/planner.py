from __future__ import annotations

import json
import os
from pathlib import Path

from spao.approval.state import assign_sections, list_sections
from spao.config import config_path, load_config
from spao.graph.store import graph_path, load_findings, load_graph
from spao.sarif.models import Finding


def fixplan_path(root: Path, finding_id: str) -> Path:
    safe_id = finding_id.replace(":", "_").replace("/", "_")
    directory = root / ".spao" / "fixplans"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / f"{safe_id}.json"


def build_fix_plan(root: Path, target: str, group_by: str | None = None) -> dict[str, object]:
    _, findings = load_findings(root)
    findings = assign_sections(findings)
    target_findings = _resolve_target_findings(findings, target, group_by)
    finding = target_findings[0]
    graph_context = _retrieve_graph_context(root, finding)
    sibling_findings = [
        item.to_dict()
        for item in findings
        if item.file == finding.file and item.id != finding.id
    ]
    section_summaries = [
        section
        for section in list_sections(findings)
        if section["file"] == finding.file
    ]

    evidence_bundle = {
        "target": target,
        "target_type": "section" if target.startswith("section:") else "finding",
        "finding": finding.to_dict(),
        "target_findings": [item.to_dict() for item in target_findings],
        "graph_path": str(graph_path(root)),
        "retrieval_backend": graph_context["backend"],
        "file_nodes": graph_context["file_nodes"],
        "symbol_nodes": graph_context["symbol_nodes"],
        "statement_nodes": graph_context["statement_nodes"],
        "line_window": graph_context["line_window"],
        "neighbor_edges": graph_context["neighbor_edges"],
        "sibling_findings": sibling_findings,
        "policy_refs": {
            "owasp": finding.owasp_refs,
            "asvs": finding.asvs_refs,
            "wstg": finding.wstg_refs,
        },
        "remediation_refs": finding.remediation_refs,
        "recommended_actions": _recommended_actions(finding),
        "multi_finding_sections": section_summaries if group_by == "file" or target.startswith("section:") else [],
    }
    return evidence_bundle


def save_fix_plan(root: Path, plan: dict[str, object]) -> Path:
    target = fixplan_path(root, str(plan["finding"]["id"]))
    target.write_text(json.dumps(plan, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return target


def _find_target(findings: list[Finding], target: str) -> Finding:
    for finding in findings:
        if finding.id == target or finding.rule_id == target:
            return finding
    if target == "first" and findings:
        return findings[0]
    raise RuntimeError(f"Unable to locate finding target: {target}")


def _resolve_target_findings(findings: list[Finding], target: str, group_by: str | None) -> list[Finding]:
    if target.startswith("section:"):
        members = [finding for finding in findings if finding.section_id == target]
        if not members:
            raise RuntimeError(f"Unable to locate finding target: {target}")
        return sorted(members, key=lambda item: (item.line_start, item.line_end, item.id))

    finding = _find_target(findings, target)
    if group_by == "file" and finding.section_id is not None:
        members = [item for item in findings if item.section_id == finding.section_id]
        return sorted(members, key=lambda item: (item.line_start, item.line_end, item.id))
    return [finding]


def _recommended_actions(finding: Finding) -> list[str]:
    actions = [
        "Review the enclosing symbol and confirm the vulnerable data flow.",
        "Apply the smallest safe fix that addresses the scanner evidence.",
        "Re-run ingest, analyze, and verify after patching.",
    ]
    if finding.cwe_refs:
        actions.append(f"Cross-check remediation against {', '.join(finding.cwe_refs)} guidance.")
    return actions


def _retrieve_graph_context(root: Path, finding: Finding) -> dict[str, object]:
    graphrag_context = _retrieve_graph_context_from_graphrag(root, finding)
    if graphrag_context is not None:
        return graphrag_context
    neo4j_context = _retrieve_graph_context_from_neo4j(root, finding)
    if neo4j_context is not None:
        return neo4j_context
    return _retrieve_graph_context_from_json(root, finding)


def _retrieve_graph_context_from_graphrag(root: Path, finding: Finding) -> dict[str, object] | None:
    try:
        from spao.graphrag.retrieval import retrieve_graphrag_context
    except ImportError:
        return None
    return retrieve_graphrag_context(root, finding)


def _retrieve_graph_context_from_json(root: Path, finding: Finding) -> dict[str, object]:
    graph = load_graph(root)
    file_nodes = [
        node.to_dict()
        for node in graph.nodes
        if node.label == "File" and node.properties.get("path") == finding.file
    ]
    symbol_nodes = [
        node.to_dict()
        for node in graph.nodes
        if node.label == "Symbol"
        and node.properties.get("file_path") == finding.file
        and int(node.properties.get("line_start", 0)) <= finding.line_start
        and int(node.properties.get("line_end", 0)) >= finding.line_end
    ]
    statement_nodes = [
        node.to_dict()
        for node in graph.nodes
        if node.label == "Statement"
        and node.properties.get("file_path") == finding.file
        and _overlaps(node.properties, finding.line_start - 3, finding.line_end + 3)
    ]
    line_window = [
        node.to_dict()
        for node in graph.nodes
        if node.label == "LineSpan"
        and node.properties.get("file_path") == finding.file
        and finding.line_start - 3 <= int(node.properties.get("line_start", 0)) <= finding.line_end + 3
    ]
    candidate_ids = {
        item["node_id"]
        for item in [*file_nodes, *symbol_nodes, *statement_nodes, *line_window]
    }
    neighbor_edges = [
        edge.to_dict()
        for edge in graph.edges
        if edge.source in candidate_ids or edge.target in candidate_ids
    ]
    return {
        "backend": "json",
        "file_nodes": file_nodes,
        "symbol_nodes": symbol_nodes,
        "statement_nodes": statement_nodes,
        "line_window": line_window,
        "neighbor_edges": neighbor_edges,
    }


def _retrieve_graph_context_from_neo4j(root: Path, finding: Finding) -> dict[str, object] | None:
    if not config_path(root).exists():
        return None
    config = load_config(root)
    password = os.environ.get(config.neo4j_password_env)
    if not password:
        return None
    try:
        from neo4j import GraphDatabase
    except ImportError:
        return None

    driver = GraphDatabase.driver(config.neo4j_uri, auth=(config.neo4j_user, password))
    window_start = max(1, finding.line_start - 3)
    window_end = finding.line_end + 3
    try:
        with driver.session() as session:
            file_nodes = session.execute_read(_query_nodes, "File", finding.file, None, None, "path")
            symbol_nodes = session.execute_read(
                _query_nodes,
                "Symbol",
                finding.file,
                finding.line_start,
                finding.line_end,
                "file_path",
            )
            statement_nodes = session.execute_read(
                _query_nodes,
                "Statement",
                finding.file,
                window_start,
                window_end,
                "file_path",
            )
            line_window = session.execute_read(
                _query_nodes,
                "LineSpan",
                finding.file,
                window_start,
                window_end,
                "file_path",
            )
            candidate_ids = [item["node_id"] for item in [*file_nodes, *symbol_nodes, *statement_nodes, *line_window]]
            neighbor_edges = session.execute_read(_query_edges_for_nodes, candidate_ids) if candidate_ids else []
    except Exception:
        return None
    finally:
        driver.close()
    return {
        "backend": "neo4j",
        "file_nodes": file_nodes,
        "symbol_nodes": symbol_nodes,
        "statement_nodes": statement_nodes,
        "line_window": line_window,
        "neighbor_edges": neighbor_edges,
    }


def _query_nodes(
    tx,
    label: str,
    path: str,
    line_start: int | None,
    line_end: int | None,
    path_key: str,
) -> list[dict[str, object]]:
    if line_start is None or line_end is None:
        result = tx.run(
            """
            MATCH (n:GraphNode)
            WHERE n.label = $label
              AND n.properties[$path_key] = $path
            RETURN n.node_id AS node_id, n.label AS label, n.properties AS properties
            ORDER BY coalesce(toInteger(n.properties.line_start), 0), coalesce(toInteger(n.properties.line_end), 0)
            """,
            label=label,
            path=path,
            path_key=path_key,
        )
    else:
        result = tx.run(
            """
            MATCH (n:GraphNode)
            WHERE n.label = $label
              AND n.properties[$path_key] = $path
              AND coalesce(toInteger(n.properties.line_start), 0) <= $line_end
              AND coalesce(toInteger(n.properties.line_end), 0) >= $line_start
            RETURN n.node_id AS node_id, n.label AS label, n.properties AS properties
            ORDER BY coalesce(toInteger(n.properties.line_start), 0), coalesce(toInteger(n.properties.line_end), 0)
            """,
            label=label,
            path=path,
            path_key=path_key,
            line_start=line_start,
            line_end=line_end,
        )
    return [dict(record) for record in result]


def _query_edges_for_nodes(tx, node_ids: list[str]) -> list[dict[str, object]]:
    result = tx.run(
        """
        MATCH (source:GraphNode)-[r]->(target:GraphNode)
        WHERE source.node_id IN $node_ids OR target.node_id IN $node_ids
        RETURN r.edge_id AS edge_id,
               r.edge_type AS edge_type,
               source.node_id AS source,
               target.node_id AS target,
               coalesce(r.properties, {}) AS properties
        ORDER BY edge_type, source, target
        """,
        node_ids=node_ids,
    )
    return [dict(record) for record in result]


def _overlaps(properties: dict[str, object], line_start: int, line_end: int) -> bool:
    start = int(properties.get("line_start", 0))
    end = int(properties.get("line_end", 0))
    return start <= line_end and end >= line_start
