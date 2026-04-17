from __future__ import annotations

import argparse
import json
from pathlib import Path

from spao.approval.state import approve_section, assign_sections, list_sections
from spao.config import SpaoConfig, config_path, load_config, save_config
from spao.fix.apply import apply_fix
from spao.fix.planner import build_fix_plan, save_fix_plan
from spao.gitops.push import record_push
from spao.gitops.service import (
    current_branch,
    current_commit,
    ensure_repo_checkout,
    normalize_public_github_url,
)
from spao.graph.backends import persist_document
from spao.graph.queries import query_graph
from spao.graph.store import load_findings, load_graph, save_findings, save_graph
from spao.indexer.ingest import build_graph
from spao.policy.catalog import enrich_findings, load_catalog
from spao.sarif.parser import parse_sarif_file
from spao.scanners.runner import run_scanners
from spao.triage.service import summarize_findings
from spao.verify.service import run_verification


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spao",
        description="Security Provenance Automated OWASP proof-of-concept CLI.",
    )
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Create the local SPAO config.")
    init_parser.add_argument(
        "--project-name",
        default=None,
        help="Override the inferred project name.",
    )

    ingest_parser = subparsers.add_parser("ingest", help="Index the repository into graph artifacts.")
    ingest_parser.add_argument(
        "--persist-neo4j",
        action="store_true",
        help="Also persist the generated graph into Neo4j using local SPAO config.",
    )
    analyze_parser = subparsers.add_parser("analyze", help="Run or import scanner results.")
    analyze_parser.add_argument(
        "--sarif",
        action="append",
        default=[],
        help="Import an existing SARIF file. May be provided more than once.",
    )

    findings_parser = subparsers.add_parser("findings", help="Finding operations.")
    findings_subparsers = findings_parser.add_subparsers(dest="findings_command")
    findings_subparsers.add_parser("list", help="List normalized findings.")

    approvals_parser = subparsers.add_parser("approvals", help="Approval section operations.")
    approvals_subparsers = approvals_parser.add_subparsers(dest="approvals_command")
    approvals_subparsers.add_parser("list", help="List grouped approval sections.")
    approvals_approve = approvals_subparsers.add_parser("approve", help="Approve a grouped section.")
    approvals_approve.add_argument("section_id")

    fix_parser = subparsers.add_parser("fix", help="Fix planning and application.")
    fix_subparsers = fix_parser.add_subparsers(dest="fix_command")
    fix_plan = fix_subparsers.add_parser("plan", help="Plan a fix for a finding.")
    fix_plan.add_argument("target")
    fix_plan.add_argument("--group-by", choices=["file"], default=None)
    fix_apply = fix_subparsers.add_parser("apply", help="Apply a fix for a finding.")
    fix_apply.add_argument("target")
    fix_apply.add_argument("--approve", action="store_true")

    graph_parser = subparsers.add_parser("graph", help="Graph inspection helpers.")
    graph_subparsers = graph_parser.add_subparsers(dest="graph_command")
    graph_query = graph_subparsers.add_parser("query", help="Query the current graph artifact.")
    graph_query.add_argument("--kind", required=True, choices=["files", "symbols", "statements", "neighbors"])
    graph_query.add_argument("--path", default=None)
    graph_query.add_argument("--line-start", type=int, default=None)
    graph_query.add_argument("--line-end", type=int, default=None)

    repo_parser = subparsers.add_parser("repo", help="Workspace repository intake helpers.")
    repo_subparsers = repo_parser.add_subparsers(dest="repo_command")
    repo_pull = repo_subparsers.add_parser("pull", help="Clone or update a public GitHub repo into the workspace.")
    repo_pull.add_argument("github_url")
    repo_pull.add_argument("--dest", default=None, help="Optional destination path inside the current workspace.")

    subparsers.add_parser("verify", help="Stub for project verification.")
    subparsers.add_parser("push", help="Stub for explicit push workflow.")
    return parser


def handle_init(args: argparse.Namespace) -> int:
    root = Path.cwd()
    project_name = args.project_name or root.name
    config = SpaoConfig(project_name=project_name)
    path = save_config(root, config)
    payload = {
        "message": "Initialized SPAO configuration.",
        "config_path": str(path),
        "branch": current_branch(root),
    }
    print(json.dumps(payload, indent=2))
    return 0


def handle_stub(command_name: str) -> int:
    payload = {
        "message": f"Command '{command_name}' is scaffolded and will be implemented in later milestones."
    }
    print(json.dumps(payload, indent=2))
    return 0


def _resolve_destination(workspace_root: Path, destination: str | None, repo_name: str) -> Path:
    candidate = workspace_root / "imports" / repo_name if destination is None else Path(destination)
    target_path = candidate if candidate.is_absolute() else workspace_root / candidate
    workspace_resolved = workspace_root.resolve()
    target_resolved = target_path.resolve()
    if not target_resolved.is_relative_to(workspace_resolved):
        raise RuntimeError("Destination path must stay inside the current workspace.")
    return target_resolved


def handle_repo_pull(github_url: str, destination: str | None) -> int:
    workspace_root = Path.cwd()
    repo_ref = normalize_public_github_url(github_url)
    target_path = _resolve_destination(workspace_root, destination, repo_ref.repo_name)
    action = ensure_repo_checkout(workspace_root, repo_ref.repo_url, target_path)

    repo_config_path = config_path(target_path)
    initialized = not repo_config_path.exists()
    if initialized:
        save_config(target_path, SpaoConfig(project_name=repo_ref.repo_name))

    payload = {
        "message": "Repository is available in the current workspace.",
        "action": action,
        "repo_url": repo_ref.repo_url,
        "repo_path": str(target_path),
        "config_path": str(repo_config_path),
        "branch": current_branch(target_path),
        "commit": current_commit(target_path),
        "initialized": initialized,
    }
    print(json.dumps(payload, indent=2))
    return 0


def handle_ingest(persist_neo4j: bool) -> int:
    root = Path.cwd()
    document = build_graph(root)
    output_path = save_graph(root, document)
    persistence: dict[str, object] | None = None
    if persist_neo4j:
        config = load_config(root)
        result = persist_document(document, config)
        persistence = {
            "backend": result.backend,
            "node_count": result.node_count,
            "edge_count": result.edge_count,
        }
    payload = {
        "message": "Repository indexed into the local graph artifact.",
        "graph_path": str(output_path),
        "metadata": document.metadata,
    }
    if persistence is not None:
        payload["persistence"] = persistence
    print(json.dumps(payload, indent=2))
    return 0


def handle_analyze(args: argparse.Namespace) -> int:
    root = Path.cwd()
    imported_paths = [Path(value).resolve() for value in args.sarif]
    scanner_artifacts = run_scanners(root)
    findings = []
    parsed_sources: list[str] = []

    for sarif_path in imported_paths:
        findings.extend(parse_sarif_file(sarif_path))
        parsed_sources.append(str(sarif_path))

    for artifact in scanner_artifacts:
        if artifact.generated and artifact.path:
            findings.extend(parse_sarif_file(Path(artifact.path)))
            parsed_sources.append(artifact.path)

    findings = assign_sections(enrich_findings(findings))
    summary = summarize_findings(findings)
    metadata = {
        "sources": parsed_sources,
        "scanner_artifacts": [artifact.to_dict() for artifact in scanner_artifacts],
        "summary": summary,
        "policy_entries": len(load_catalog()),
    }
    output_path = save_findings(root, findings, metadata)
    payload = {
        "message": "Scanner results normalized into findings artifact.",
        "findings_path": str(output_path),
        "summary": summary,
    }
    print(json.dumps(payload, indent=2))
    return 0


def handle_findings_list() -> int:
    root = Path.cwd()
    metadata, findings = load_findings(root)
    payload = {
        "metadata": metadata,
        "findings": [finding.to_dict() for finding in findings],
    }
    print(json.dumps(payload, indent=2))
    return 0


def handle_approvals_list() -> int:
    root = Path.cwd()
    _, findings = load_findings(root)
    payload = {"sections": list_sections(findings)}
    print(json.dumps(payload, indent=2))
    return 0


def handle_approvals_approve(section_id: str) -> int:
    root = Path.cwd()
    metadata, findings = load_findings(root)
    updated = approve_section(findings, section_id)
    save_findings(root, updated, metadata)
    payload = {"message": "Approval section updated.", "section_id": section_id}
    print(json.dumps(payload, indent=2))
    return 0


def handle_graph_query(kind: str, path: str | None, line_start: int | None, line_end: int | None) -> int:
    root = Path.cwd()
    document = load_graph(root)
    payload = query_graph(
        document,
        kind=kind,
        path=path,
        line_start=line_start,
        line_end=line_end,
    )
    print(json.dumps(payload, indent=2))
    return 0


def handle_fix_plan(target: str, group_by: str | None) -> int:
    root = Path.cwd()
    plan = build_fix_plan(root, target, group_by=group_by)
    output_path = save_fix_plan(root, plan)
    payload = {
        "message": "Deterministic evidence bundle created for fix planning.",
        "plan_path": str(output_path),
        "finding_id": plan["finding"]["id"],
        "symbol_count": len(plan["symbol_nodes"]),
        "line_window_count": len(plan["line_window"]),
        "target_findings": [item["id"] for item in plan.get("target_findings", [])],
    }
    print(json.dumps(payload, indent=2))
    return 0


def handle_fix_apply(target: str, approve: bool) -> int:
    root = Path.cwd()
    result = apply_fix(root, target, approve)
    payload = {
        "message": "Patch applied for the requested finding.",
        **result,
    }
    print(json.dumps(payload, indent=2))
    return 0


def handle_verify() -> int:
    root = Path.cwd()
    payload = run_verification(root)
    print(json.dumps(payload, indent=2))
    return 0


def handle_push() -> int:
    root = Path.cwd()
    payload = record_push(root)
    payload["message"] = "Current branch pushed and push metadata recorded."
    print(json.dumps(payload, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "init":
            return handle_init(args)
        if args.command == "ingest":
            return handle_ingest(args.persist_neo4j)
        if args.command == "analyze":
            return handle_analyze(args)
        if args.command == "findings" and args.findings_command == "list":
            return handle_findings_list()
        if args.command == "approvals" and args.approvals_command == "list":
            return handle_approvals_list()
        if args.command == "approvals" and args.approvals_command == "approve":
            return handle_approvals_approve(args.section_id)
        if args.command == "graph" and args.graph_command == "query":
            return handle_graph_query(args.kind, args.path, args.line_start, args.line_end)
        if args.command == "repo" and args.repo_command == "pull":
            return handle_repo_pull(args.github_url, args.dest)
        if args.command == "fix" and args.fix_command == "plan":
            return handle_fix_plan(args.target, args.group_by)
        if args.command == "fix" and args.fix_command == "apply":
            return handle_fix_apply(args.target, args.approve)
        if args.command == "verify":
            return handle_verify()
        if args.command == "push":
            return handle_push()
    except RuntimeError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 1

    parser.print_help()
    return 0
