from __future__ import annotations

import json
import difflib
from pathlib import Path

from spao.approval.state import assign_sections, require_approval, require_section_approval
from spao.fix.planner import build_fix_plan, save_fix_plan
from spao.fix.providers import HeuristicPatchProvider
from spao.graph.store import load_findings, save_findings


def patches_dir(root: Path) -> Path:
    directory = root / ".spao" / "patches"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def apply_fix(root: Path, target: str, approve: bool) -> dict[str, object]:
    require_approval(approve)
    metadata, findings = load_findings(root)
    findings = assign_sections(findings)
    is_section_target = target.startswith("section:")
    if is_section_target:
        require_section_approval(findings, target)

    plan = build_fix_plan(root, target, group_by="file" if is_section_target else None)
    plan["repo_root"] = str(root)
    save_fix_plan(root, plan)
    provider = HeuristicPatchProvider()
    file_path = root / str(plan["finding"]["file"])
    original = file_path.read_text(encoding="utf-8")
    updated = original
    proposals = []

    for target_finding in plan.get("target_findings", [plan["finding"]]):
        finding_plan = build_fix_plan(root, str(target_finding["id"]))
        finding_plan["repo_root"] = str(root)
        proposal = provider.generate_patch(finding_plan, original_content=updated)
        proposals.append(proposal)
        updated = proposal.updated_content

    file_path.write_text(updated, encoding="utf-8")

    patch_file = patches_dir(root) / f"{str(plan['finding']['id']).replace(':', '_')}.diff"
    combined_diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=str(file_path.relative_to(root)),
            tofile=str(file_path.relative_to(root)),
        )
    )
    patch_file.write_text(combined_diff, encoding="utf-8")

    updated_findings = []
    applied_ids = {item["id"] for item in plan.get("target_findings", [plan["finding"]])}
    for finding in findings:
        if finding.id in applied_ids:
            finding.approval_state = "patch_applied"
        updated_findings.append(finding)
    updated_findings = assign_sections(updated_findings)
    save_findings(root, updated_findings, metadata)

    result = {
        "finding_id": plan["finding"]["id"],
        "section_id": plan["finding"].get("section_id"),
        "applied_findings": [finding_id for proposal in proposals for finding_id in proposal.finding_ids],
        "file_path": str(file_path),
        "patch_path": str(patch_file),
        "rationale": " ".join(proposal.rationale for proposal in proposals),
        "remediation_family": ",".join(proposal.remediation_family for proposal in proposals),
    }
    result_path = patches_dir(root) / f"{str(plan['finding']['id']).replace(':', '_')}.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
