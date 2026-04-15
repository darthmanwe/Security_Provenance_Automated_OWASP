from __future__ import annotations


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
