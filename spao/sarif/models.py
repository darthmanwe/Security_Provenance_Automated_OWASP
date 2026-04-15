from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class Finding:
    id: str
    tool: str
    rule_id: str
    title: str
    message: str
    language: str
    file: str
    line_start: int
    line_end: int
    symbol: str | None
    severity: str
    confidence: str
    fingerprint: str
    cwe_refs: list[str] = field(default_factory=list)
    owasp_refs: list[str] = field(default_factory=list)
    asvs_refs: list[str] = field(default_factory=list)
    wstg_refs: list[str] = field(default_factory=list)
    evidence_subgraph_id: str | None = None
    remediation_refs: list[str] = field(default_factory=list)
    approval_state: str = "detected"
    verification_state: str = "not_run"
    push_state: str = "not_pushed"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
