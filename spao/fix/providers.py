from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import difflib


@dataclass(slots=True)
class PatchProposal:
    unified_diff: str
    rationale: str


class LLMProvider:
    def generate_patch(self, evidence_bundle: dict[str, object]) -> PatchProposal:
        raise NotImplementedError


class NoopLLMProvider(LLMProvider):
    def generate_patch(self, evidence_bundle: dict[str, object]) -> PatchProposal:
        finding = evidence_bundle["finding"]
        return PatchProposal(
            unified_diff="",
            rationale=(
                "No LLM provider configured. Review the evidence bundle and apply a manual fix "
                f"for finding {finding['id']}."
            ),
        )


class HeuristicPatchProvider(LLMProvider):
    def generate_patch(self, evidence_bundle: dict[str, object]) -> PatchProposal:
        finding = evidence_bundle["finding"]
        file_path = Path(str(finding["file"]))
        root = Path(str(evidence_bundle["repo_root"]))
        absolute_path = root / file_path
        original = absolute_path.read_text(encoding="utf-8")
        updated = _rewrite_content(original, finding)
        if updated == original:
            raise RuntimeError(
                f"No heuristic patch available for finding {finding['id']} ({finding['rule_id']})."
            )
        diff = "".join(
            difflib.unified_diff(
                original.splitlines(keepends=True),
                updated.splitlines(keepends=True),
                fromfile=str(file_path),
                tofile=str(file_path),
            )
        )
        return PatchProposal(
            unified_diff=diff,
            rationale="Applied a deterministic heuristic patch based on the current finding metadata.",
        )


def _rewrite_content(original: str, finding: dict[str, object]) -> str:
    rule_id = str(finding["rule_id"]).lower()
    cwe_refs = [str(item).upper() for item in finding.get("cwe_refs", [])]
    file_name = str(finding["file"])
    if file_name.endswith(".py") and ("eval" in rule_id or "CWE-95" in cwe_refs):
        updated = original.replace("eval(", "literal_eval(")
        if updated == original:
            return original
        if "from ast import literal_eval" not in updated:
            lines = updated.splitlines()
            insertion_index = 0
            while insertion_index < len(lines) and lines[insertion_index].startswith(("import ", "from ")):
                insertion_index += 1
            lines.insert(insertion_index, "from ast import literal_eval")
            updated = "\n".join(lines)
            if original.endswith("\n"):
                updated += "\n"
        return updated
    return original
