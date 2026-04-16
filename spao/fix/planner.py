from __future__ import annotations

import json
from pathlib import Path

from spao.approval.state import assign_sections, list_sections
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
    graph = load_graph(root)

    file_nodes = [
        node
        for node in graph.nodes
        if node.label == "File" and node.properties.get("path") == finding.file
    ]
    symbol_nodes = [
        node
        for node in graph.nodes
        if node.label == "Symbol"
        and node.properties.get("file_path") == finding.file
        and int(node.properties.get("line_start", 0)) <= finding.line_start
        and int(node.properties.get("line_end", 0)) >= finding.line_end
    ]
    line_nodes = [
        node
        for node in graph.nodes
        if node.label == "LineSpan"
        and node.properties.get("file_path") == finding.file
        and finding.line_start - 3 <= int(node.properties.get("line_start", 0)) <= finding.line_end + 3
    ]
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
        "file_nodes": [node.to_dict() for node in file_nodes],
        "symbol_nodes": [node.to_dict() for node in symbol_nodes],
        "line_window": [node.to_dict() for node in line_nodes],
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
