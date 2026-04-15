from __future__ import annotations

from dataclasses import dataclass


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
