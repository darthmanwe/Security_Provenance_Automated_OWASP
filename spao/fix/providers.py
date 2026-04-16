from __future__ import annotations

import ast
import json
from dataclasses import dataclass
from pathlib import Path
import difflib
import re


@dataclass(slots=True)
class PatchProposal:
    unified_diff: str
    updated_content: str
    rationale: str
    finding_ids: list[str]
    remediation_family: str


class LLMProvider:
    def generate_patch(self, evidence_bundle: dict[str, object]) -> PatchProposal:
        raise NotImplementedError


class NoopLLMProvider(LLMProvider):
    def generate_patch(self, evidence_bundle: dict[str, object]) -> PatchProposal:
        finding = evidence_bundle["finding"]
        return PatchProposal(
            unified_diff="",
            updated_content="",
            rationale=(
                "No LLM provider configured. Review the evidence bundle and apply a manual fix "
                f"for finding {finding['id']}."
            ),
            finding_ids=[str(finding["id"])],
            remediation_family="none",
        )


class HeuristicPatchProvider(LLMProvider):
    def __init__(self) -> None:
        self.families: list[RemediationFamily] = [
            PythonEvalRemediationFamily(),
            JsTsDynamicExecutionRemediationFamily(),
        ]

    def generate_patch(self, evidence_bundle: dict[str, object]) -> PatchProposal:
        finding = evidence_bundle["finding"]
        file_path = Path(str(finding["file"]))
        root = Path(str(evidence_bundle["repo_root"]))
        absolute_path = root / file_path
        original = absolute_path.read_text(encoding="utf-8")
        for family in self.families:
            if not family.matches(finding):
                continue
            updated = family.rewrite_content(original, finding)
            if updated == original:
                continue
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
                updated_content=updated,
                rationale=family.rationale(finding),
                finding_ids=[str(finding["id"])],
                remediation_family=family.family_name,
            )
        raise RuntimeError(
            f"No heuristic patch available for finding {finding['id']} ({finding['rule_id']})."
        )


class RemediationFamily:
    family_name = "base"

    def matches(self, finding: dict[str, object]) -> bool:
        raise NotImplementedError

    def rewrite_content(self, original: str, finding: dict[str, object]) -> str:
        raise NotImplementedError

    def rationale(self, finding: dict[str, object]) -> str:
        return "Applied a deterministic heuristic patch based on the current finding metadata."


class PythonEvalRemediationFamily(RemediationFamily):
    family_name = "python_eval_literal_eval"

    def matches(self, finding: dict[str, object]) -> bool:
        rule_id = str(finding["rule_id"]).lower()
        cwe_refs = [str(item).upper() for item in finding.get("cwe_refs", [])]
        file_name = str(finding["file"])
        return file_name.endswith(".py") and ("eval" in rule_id or "CWE-95" in cwe_refs)

    def rewrite_content(self, original: str, finding: dict[str, object]) -> str:
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

    def rationale(self, finding: dict[str, object]) -> str:
        return "Replaced Python eval() with ast.literal_eval() for the supported CWE-95 remediation path."


class JsTsDynamicExecutionRemediationFamily(RemediationFamily):
    family_name = "js_ts_dynamic_execution_literals"

    EVAL_PATTERN = re.compile(r"eval\(\s*(?P<literal>'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")\s*\)")
    FUNCTION_PATTERN = re.compile(
        r"new\s+Function\(\s*(?P<literal>'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")\s*\)\s*\(\s*\)"
    )

    def matches(self, finding: dict[str, object]) -> bool:
        rule_id = str(finding["rule_id"]).lower()
        cwe_refs = [str(item).upper() for item in finding.get("cwe_refs", [])]
        file_name = str(finding["file"])
        is_target_language = file_name.endswith(".js") or file_name.endswith(".ts")
        return is_target_language and (
            "eval" in rule_id or "function" in rule_id or "CWE-95" in cwe_refs
        )

    def rewrite_content(self, original: str, finding: dict[str, object]) -> str:
        updated = self.EVAL_PATTERN.sub(self._rewrite_eval_match, original, count=1)
        if updated != original:
            return updated
        return self.FUNCTION_PATTERN.sub(self._rewrite_function_match, original, count=1)

    def rationale(self, finding: dict[str, object]) -> str:
        return (
            "Replaced literal-based JavaScript/TypeScript dynamic execution with JSON.parse() "
            "for a tightly bounded supported heuristic."
        )

    def _rewrite_eval_match(self, match: re.Match[str]) -> str:
        literal = match.group("literal")
        decoded = _decode_js_string_literal(literal)
        _ensure_json_literal(decoded)
        return f"JSON.parse({json.dumps(decoded)})"

    def _rewrite_function_match(self, match: re.Match[str]) -> str:
        literal = match.group("literal")
        decoded = _decode_js_string_literal(literal)
        body_match = re.fullmatch(r"\s*return\s+(?P<expression>.+?);?\s*", decoded, flags=re.DOTALL)
        if body_match is None:
            return match.group(0)
        expression = body_match.group("expression").strip()
        _ensure_json_literal(expression)
        return f"JSON.parse({json.dumps(expression)})"


def _decode_js_string_literal(literal: str) -> str:
    try:
        return ast.literal_eval(literal)
    except (ValueError, SyntaxError) as exc:
        raise RuntimeError(f"Unable to decode JavaScript literal for remediation: {literal}") from exc


def _ensure_json_literal(raw_text: str) -> None:
    try:
        json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Only literal JSON payloads are supported for JS/TS auto-remediation.") from exc
