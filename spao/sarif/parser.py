from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spao.sarif.models import Finding


LEVEL_MAP = {
    "error": "high",
    "warning": "medium",
    "note": "low",
    "none": "info",
}


def _fingerprint(tool: str, rule_id: str, file_path: str, start_line: int, message: str) -> str:
    raw = "::".join([tool, rule_id, file_path, str(start_line), message])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_sarif_file(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []

    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "unknown")
        rule_index: dict[str, dict[str, object]] = {}
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rule_id = str(rule.get("id", "unknown"))
            rule_index[rule_id] = rule

        for result in run.get("results", []):
            rule_id = str(result.get("ruleId", "unknown"))
            rule = rule_index.get(rule_id, {})
            locations = result.get("locations") or [{}]
            physical = locations[0].get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})
            file_path = artifact.get("uri", "")
            start_line = int(region.get("startLine", 1))
            end_line = int(region.get("endLine", start_line))
            message = result.get("message", {}).get("text", "")
            level = str(result.get("level", "warning")).lower()
            properties = {**rule.get("properties", {}), **result.get("properties", {})}
            tags = [str(tag) for tag in properties.get("tags", [])]
            cwe_refs = [tag for tag in tags if tag.upper().startswith("CWE-")]
            owasp_refs = [tag for tag in tags if "owasp" in tag.lower()]
            language = _infer_language(file_path)
            fingerprint = _fingerprint(tool, rule_id, file_path, start_line, message)
            finding = Finding(
                id=f"{tool}:{rule_id}:{fingerprint[:12]}",
                tool=tool,
                rule_id=rule_id,
                title=str(rule.get("name") or rule.get("shortDescription", {}).get("text") or rule_id),
                message=message,
                language=language,
                file=file_path,
                line_start=start_line,
                line_end=end_line,
                symbol=None,
                severity=LEVEL_MAP.get(level, "medium"),
                confidence="medium",
                fingerprint=fingerprint,
                cwe_refs=cwe_refs,
                owasp_refs=owasp_refs,
                remediation_refs=[
                    str(link.get("uri"))
                    for link in rule.get("helpUri", [])  # type: ignore[arg-type]
                ]
                if isinstance(rule.get("helpUri"), list)
                else ([str(rule.get("helpUri"))] if rule.get("helpUri") else []),
            )
            findings.append(finding)

    return findings


def _infer_language(file_path: str) -> str:
    if file_path.endswith(".py"):
        return "python"
    if file_path.endswith(".ts"):
        return "typescript"
    if file_path.endswith(".js"):
        return "javascript"
    return "unknown"
