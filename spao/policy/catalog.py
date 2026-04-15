from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from spao.sarif.models import Finding


@dataclass(slots=True)
class PolicyEntry:
    id: str
    title: str
    source: str
    aliases: list[str]
    cwe_refs: list[str]
    remediation_refs: list[str]


def _catalog_dir() -> Path:
    return Path(__file__).resolve().parent / "catalogs"


def load_catalog() -> list[PolicyEntry]:
    entries: list[PolicyEntry] = []
    for path in sorted(_catalog_dir().glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data:
            entries.append(
                PolicyEntry(
                    id=item["id"],
                    title=item["title"],
                    source=item["source"],
                    aliases=item.get("aliases", []),
                    cwe_refs=item.get("cwe_refs", []),
                    remediation_refs=item.get("remediation_refs", []),
                )
            )
    return entries


def enrich_findings(findings: list[Finding]) -> list[Finding]:
    catalog = load_catalog()
    alias_map = {
        alias.lower(): entry
        for entry in catalog
        for alias in [entry.id, *entry.aliases]
    }
    cwe_map: dict[str, list[PolicyEntry]] = {}
    for entry in catalog:
        for cwe in entry.cwe_refs:
            cwe_map.setdefault(cwe.upper(), []).append(entry)

    enriched: list[Finding] = []
    for finding in findings:
        owasp_refs = set(finding.owasp_refs)
        asvs_refs = set(finding.asvs_refs)
        wstg_refs = set(finding.wstg_refs)
        remediation_refs = set(finding.remediation_refs)

        for ref in list(finding.owasp_refs):
            entry = alias_map.get(ref.lower())
            if entry:
                _attach_entry(entry, owasp_refs, asvs_refs, wstg_refs, remediation_refs)

        for cwe in finding.cwe_refs:
            for entry in cwe_map.get(cwe.upper(), []):
                _attach_entry(entry, owasp_refs, asvs_refs, wstg_refs, remediation_refs)

        finding.owasp_refs = sorted(owasp_refs)
        finding.asvs_refs = sorted(asvs_refs)
        finding.wstg_refs = sorted(wstg_refs)
        finding.remediation_refs = sorted(remediation_refs)
        enriched.append(finding)

    return enriched


def _attach_entry(
    entry: PolicyEntry,
    owasp_refs: set[str],
    asvs_refs: set[str],
    wstg_refs: set[str],
    remediation_refs: set[str],
) -> None:
    if entry.source in {"owasp_top10", "owasp_api_top10", "owasp_mobile_top10"}:
        owasp_refs.add(entry.id)
    elif entry.source == "owasp_asvs":
        asvs_refs.add(entry.id)
    elif entry.source == "owasp_wstg":
        wstg_refs.add(entry.id)

    remediation_refs.update(entry.remediation_refs)
