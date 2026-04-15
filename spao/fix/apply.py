from __future__ import annotations

import json
from pathlib import Path

from spao.approval.state import require_approval
from spao.fix.planner import build_fix_plan, save_fix_plan
from spao.fix.providers import HeuristicPatchProvider
from spao.graph.store import load_findings, save_findings


def patches_dir(root: Path) -> Path:
    directory = root / ".spao" / "patches"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def apply_fix(root: Path, target: str, approve: bool) -> dict[str, object]:
    require_approval(approve)
    plan = build_fix_plan(root, target)
    plan["repo_root"] = str(root)
    save_fix_plan(root, plan)
    provider = HeuristicPatchProvider()
    proposal = provider.generate_patch(plan)

    file_path = root / str(plan["finding"]["file"])
    original = file_path.read_text(encoding="utf-8")
    updated = _apply_diff_heuristic(original, plan)
    file_path.write_text(updated, encoding="utf-8")

    patch_file = patches_dir(root) / f"{str(plan['finding']['id']).replace(':', '_')}.diff"
    patch_file.write_text(proposal.unified_diff, encoding="utf-8")

    metadata, findings = load_findings(root)
    updated_findings = []
    for finding in findings:
        if finding.id == plan["finding"]["id"]:
            finding.approval_state = "patch_applied"
        updated_findings.append(finding)
    save_findings(root, updated_findings, metadata)

    result = {
        "finding_id": plan["finding"]["id"],
        "file_path": str(file_path),
        "patch_path": str(patch_file),
        "rationale": proposal.rationale,
    }
    result_path = patches_dir(root) / f"{str(plan['finding']['id']).replace(':', '_')}.json"
    result_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def _apply_diff_heuristic(original: str, plan: dict[str, object]) -> str:
    from spao.fix.providers import _rewrite_content

    return _rewrite_content(original, plan["finding"])
