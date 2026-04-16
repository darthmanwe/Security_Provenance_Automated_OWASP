from __future__ import annotations

import hashlib

from spao.sarif.models import Finding


APPROVAL_STATES = {
    "detected",
    "section_approved",
    "patch_applied",
    "verification_passed",
    "ready_to_push",
}


def require_approval(approved: bool) -> None:
    if not approved:
        raise RuntimeError("Patch application requires --approve for this PoC workflow.")


def assign_sections(findings: list[Finding]) -> list[Finding]:
    by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    for file_findings in by_file.values():
        sorted_findings = sorted(file_findings, key=lambda item: (item.line_start, item.line_end, item.id))
        groups: list[list[Finding]] = []
        current_group: list[Finding] = []
        current_end = 0
        for finding in sorted_findings:
            if not current_group or finding.line_start <= current_end + 3:
                current_group.append(finding)
                current_end = max(current_end, finding.line_end)
            else:
                groups.append(current_group)
                current_group = [finding]
                current_end = finding.line_end
        if current_group:
            groups.append(current_group)

        for group in groups:
            section_id = _section_id(
                group[0].file,
                min(item.line_start for item in group),
                max(item.line_end for item in group),
            )
            grouped_ids = [item.id for item in group]
            status = _section_status(group)
            for finding in group:
                finding.section_id = section_id
                finding.section_status = status
                finding.grouped_finding_ids = grouped_ids
    return findings


def list_sections(findings: list[Finding]) -> list[dict[str, object]]:
    sections: dict[str, dict[str, object]] = {}
    for finding in assign_sections(findings):
        assert finding.section_id is not None
        section = sections.setdefault(
            finding.section_id,
            {
                "section_id": finding.section_id,
                "file": finding.file,
                "status": finding.section_status,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "finding_ids": [],
            },
        )
        section["line_start"] = min(int(section["line_start"]), finding.line_start)
        section["line_end"] = max(int(section["line_end"]), finding.line_end)
        section["finding_ids"].append(finding.id)
        section["status"] = _section_status_from_strings([str(section["status"]), finding.section_status])
    return sorted(sections.values(), key=lambda item: (str(item["file"]), int(item["line_start"])))


def approve_section(findings: list[Finding], section_id: str) -> list[Finding]:
    findings = assign_sections(findings)
    matched = False
    for finding in findings:
        if finding.section_id == section_id:
            finding.approval_state = "section_approved"
            matched = True
    if not matched:
        raise RuntimeError(f"Unable to locate approval section: {section_id}")
    return assign_sections(findings)


def require_section_approval(findings: list[Finding], section_id: str) -> None:
    findings = assign_sections(findings)
    members = [finding for finding in findings if finding.section_id == section_id]
    if not members:
        raise RuntimeError(f"Unable to locate approval section: {section_id}")
    if any(finding.section_status == "pending" for finding in members):
        raise RuntimeError(
            f"Section {section_id} must be approved with 'spao approvals approve {section_id}' before grouped apply."
        )


def _section_id(file_path: str, line_start: int, line_end: int) -> str:
    digest = hashlib.sha256(f"{file_path}:{line_start}:{line_end}".encode("utf-8")).hexdigest()[:12]
    return f"section:{digest}"


def _section_status(findings: list[Finding]) -> str:
    return _section_status_from_strings([finding.approval_state for finding in findings])


def _section_status_from_strings(states: list[str]) -> str:
    if all(state in {"patch_applied", "verification_passed", "ready_to_push"} for state in states):
        return "applied"
    if all(state in {"section_approved", "patch_applied", "verification_passed", "ready_to_push"} for state in states):
        return "approved"
    return "pending"
