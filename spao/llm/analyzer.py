"""Codebase-level LLM analysis using the Anthropic provider.

Orchestrates graph stats, findings, and file metadata into a single
Claude call that produces a senior-engineer-level security assessment.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path

from spao.fix.providers import AnthropicLLMProvider, LLMAnalysis
from spao.graph.store import load_graph, load_findings
from spao.fix.planner import build_fix_plan


def _graph_stats(root: Path) -> dict:
    graph = load_graph(root)
    label_counts: dict[str, int] = {}
    for node in graph.nodes:
        label_counts[node.label] = label_counts.get(node.label, 0) + 1
    edge_type_counts: dict[str, int] = {}
    for edge in graph.edges:
        edge_type_counts[edge.edge_type] = edge_type_counts.get(edge.edge_type, 0) + 1
    return {
        "total_nodes": len(graph.nodes),
        "total_edges": len(graph.edges),
        "node_labels": label_counts,
        "edge_types": edge_type_counts,
        "metadata": graph.metadata,
    }


def _findings_summary(root: Path) -> dict:
    try:
        metadata, findings = load_findings(root)
    except FileNotFoundError:
        return {"total": 0, "findings": [], "metadata": {}}

    by_severity: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    by_cwe: dict[str, int] = {}
    by_file: dict[str, int] = {}

    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        for ref in f.owasp_refs:
            by_owasp[ref] = by_owasp.get(ref, 0) + 1
        for ref in f.cwe_refs:
            by_cwe[ref] = by_cwe.get(ref, 0) + 1
        by_file[f.file] = by_file.get(f.file, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_owasp": by_owasp,
        "by_cwe": by_cwe,
        "by_file": by_file,
        "metadata": metadata,
        "findings": [f.to_dict() for f in findings],
    }


def _file_list_from_graph(root: Path) -> list[str]:
    graph = load_graph(root)
    return sorted({
        str(node.properties.get("path", ""))
        for node in graph.nodes
        if node.label == "File"
    })


def analyze_finding_with_llm(root: Path, finding_id: str) -> LLMAnalysis:
    """Run LLM analysis on a single finding using its evidence bundle."""
    plan = build_fix_plan(root, finding_id)
    provider = AnthropicLLMProvider()
    return provider.analyze_finding(plan)


def analyze_codebase_with_llm(root: Path) -> str:
    """Run a full codebase-level LLM assessment."""
    stats = _graph_stats(root)
    summary = _findings_summary(root)
    files = _file_list_from_graph(root)
    provider = AnthropicLLMProvider()
    return provider.analyze_codebase(stats, summary, files)


def run_full_llm_report(root: Path) -> dict:
    """Run graph stats collection, findings summary, and LLM analysis.

    Returns a dict with all raw data plus the LLM narrative.
    """
    stats = _graph_stats(root)
    summary = _findings_summary(root)
    files = _file_list_from_graph(root)

    llm_narrative = ""
    finding_analyses: list[dict] = []

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        provider = AnthropicLLMProvider(api_key=api_key)
        try:
            llm_narrative = provider.analyze_codebase(stats, summary, files)
        except Exception as exc:
            llm_narrative = f"LLM analysis unavailable: {exc}"

        for finding_data in summary.get("findings", [])[:10]:
            try:
                plan = build_fix_plan(root, str(finding_data["id"]))
                analysis = provider.analyze_finding(plan)
                finding_analyses.append({
                    "finding_id": finding_data["id"],
                    "analysis": asdict(analysis),
                })
            except Exception:
                continue

    return {
        "graph_stats": stats,
        "findings_summary": summary,
        "indexed_files": files,
        "llm_narrative": llm_narrative,
        "finding_analyses": finding_analyses,
    }
