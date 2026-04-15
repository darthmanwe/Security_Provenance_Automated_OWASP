from __future__ import annotations

import argparse
import json
from pathlib import Path

from spao.config import SpaoConfig, config_path, save_config
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
    subparsers.add_parser("analyze", help="Stub for scanner execution.")

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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "init":
        return handle_init(args)
    if args.command == "ingest":
        return handle_stub("ingest")
    if args.command == "analyze":
        return handle_stub("analyze")
    if args.command == "findings" and args.findings_command == "list":
        return handle_stub("findings list")
    if args.command == "fix" and args.fix_command == "plan":
        return handle_stub(f"fix plan {args.target}")
    if args.command == "fix" and args.fix_command == "apply":
        return handle_stub(f"fix apply {args.target}")
    if args.command == "verify":
        return handle_stub("verify")
    if args.command == "push":
        return handle_stub("push")

    parser.print_help()
    return 0
