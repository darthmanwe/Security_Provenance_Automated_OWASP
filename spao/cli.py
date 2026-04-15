from __future__ import annotations

import argparse
import json
from pathlib import Path

from spao.config import SpaoConfig, save_config
from spao.fix.apply import apply_fix
from spao.fix.planner import build_fix_plan, save_fix_plan
from spao.gitops.push import record_push
from spao.graph.store import load_findings, save_findings, save_graph
from spao.indexer.ingest import build_graph
from spao.policy.catalog import enrich_findings, load_catalog
from spao.sarif.parser import parse_sarif_file
from spao.scanners.runner import run_scanners
from spao.triage.service import summarize_findings
from spao.verify.service import run_verification
from spao.gitops.service import current_branch


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

    subparsers.add_parser("ingest", help="Stub for repo ingestion.")
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

    fix_parser = subparsers.add_parser("fix", help="Fix planning and application.")
    fix_subparsers = fix_parser.add_subparsers(dest="fix_command")
    fix_plan = fix_subparsers.add_parser("plan", help="Plan a fix for a finding.")
    fix_plan.add_argument("target")
    fix_apply = fix_subparsers.add_parser("apply", help="Apply a fix for a finding.")
    fix_apply.add_argument("target")
    fix_apply.add_argument("--approve", action="store_true")

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


def handle_ingest() -> int:
    root = Path.cwd()
    document = build_graph(root)
    output_path = save_graph(root, document)
    payload = {
        "message": "Repository indexed into the local graph artifact.",
        "graph_path": str(output_path),
        "metadata": document.metadata,
    }
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

    findings = enrich_findings(findings)
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


def handle_fix_plan(target: str) -> int:
    root = Path.cwd()
    plan = build_fix_plan(root, target)
    output_path = save_fix_plan(root, plan)
    payload = {
        "message": "Deterministic evidence bundle created for fix planning.",
        "plan_path": str(output_path),
        "finding_id": plan["finding"]["id"],
        "symbol_count": len(plan["symbol_nodes"]),
        "line_window_count": len(plan["line_window"]),
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
            return handle_ingest()
        if args.command == "analyze":
            return handle_analyze(args)
        if args.command == "findings" and args.findings_command == "list":
            return handle_findings_list()
        if args.command == "fix" and args.fix_command == "plan":
            return handle_fix_plan(args.target)
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
