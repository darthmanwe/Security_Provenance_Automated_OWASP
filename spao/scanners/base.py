from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(slots=True)
class ScannerArtifact:
    tool: str
    path: str
    generated: bool
    status: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
