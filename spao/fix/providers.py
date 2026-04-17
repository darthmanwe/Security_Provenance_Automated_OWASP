from __future__ import annotations

import ast
import json
import os
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


@dataclass(slots=True)
class LLMAnalysis:
    risk_narrative: str
    severity_assessment: str
    owasp_commentary: str
    remediation_guidance: str
    graph_context_summary: str
    confidence: float


class LLMProvider:
    def generate_patch(
        self, evidence_bundle: dict[str, object], original_content: str | None = None
    ) -> PatchProposal:
        raise NotImplementedError

    def analyze_finding(self, evidence_bundle: dict[str, object]) -> LLMAnalysis | None:
        return None


class NoopLLMProvider(LLMProvider):
    def generate_patch(
        self, evidence_bundle: dict[str, object], original_content: str | None = None
    ) -> PatchProposal:
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


class AnthropicLLMProvider(LLMProvider):
    """Uses Claude via the Anthropic API for enhanced fix rationale and finding analysis."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514") -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = model
        self._client = None

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError:
            raise RuntimeError(
                "The anthropic package is required for LLM-powered analysis. "
                "Install it with: pip install anthropic"
            )
        if not self.api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Provide it via the environment or constructor."
            )
        self._client = anthropic.Anthropic(api_key=self.api_key)
        return self._client

    def generate_patch(
        self, evidence_bundle: dict[str, object], original_content: str | None = None
    ) -> PatchProposal:
        finding = evidence_bundle["finding"]
        file_path = Path(str(finding["file"]))
        root = Path(str(evidence_bundle["repo_root"]))
        absolute_path = root / file_path
        original = original_content if original_content is not None else absolute_path.read_text(encoding="utf-8")

        prompt = self._build_patch_prompt(evidence_bundle, original)
        client = self._get_client()
        message = client.messages.create(
            model=self.model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        response_text = message.content[0].text

        return PatchProposal(
            unified_diff="",
            updated_content=original,
            rationale=response_text,
            finding_ids=[str(finding["id"])],
            remediation_family="llm_anthropic",
        )

    def analyze_finding(self, evidence_bundle: dict[str, object]) -> LLMAnalysis:
        prompt = self._build_analysis_prompt(evidence_bundle)
        client = self._get_client()
        message = client.messages.create(
            model=self.model,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )
        response_text = message.content[0].text
        return self._parse_analysis_response(response_text)

    def analyze_codebase(self, graph_stats: dict, findings_summary: dict, file_list: list[str]) -> str:
        prompt = self._build_codebase_analysis_prompt(graph_stats, findings_summary, file_list)
        client = self._get_client()
        message = client.messages.create(
            model=self.model,
            max_tokens=8192,
            messages=[{"role": "user", "content": prompt}],
        )
        return message.content[0].text

    def _build_patch_prompt(self, evidence_bundle: dict[str, object], original: str) -> str:
        finding = evidence_bundle["finding"]
        symbols = evidence_bundle.get("symbol_nodes", [])
        policy = evidence_bundle.get("policy_refs", {})
        return (
            "You are a senior security engineer reviewing a vulnerability finding.\n\n"
            f"File: {finding['file']}\n"
            f"Rule: {finding['rule_id']}\n"
            f"CWE: {', '.join(finding.get('cwe_refs', []))}\n"
            f"OWASP: {', '.join(policy.get('owasp', []))}\n"
            f"Severity: {finding['severity']}\n"
            f"Line: {finding['line_start']}-{finding['line_end']}\n\n"
            f"Enclosing symbols: {json.dumps(symbols, indent=2)[:2000]}\n\n"
            f"Source code:\n```\n{original[:4000]}\n```\n\n"
            "Provide:\n"
            "1. A concise risk assessment for this finding\n"
            "2. The recommended remediation approach\n"
            "3. Any caveats or edge cases to watch for\n"
        )

    def _build_analysis_prompt(self, evidence_bundle: dict[str, object]) -> str:
        finding = evidence_bundle["finding"]
        policy = evidence_bundle.get("policy_refs", {})
        return (
            "You are a senior security-focused ML/AI engineer analyzing a security finding "
            "from a graph-backed code analysis system.\n\n"
            "Respond in exactly this format with these section headers:\n"
            "RISK_NARRATIVE: <paragraph>\n"
            "SEVERITY_ASSESSMENT: <paragraph>\n"
            "OWASP_COMMENTARY: <paragraph>\n"
            "REMEDIATION_GUIDANCE: <paragraph>\n"
            "GRAPH_CONTEXT_SUMMARY: <paragraph>\n"
            "CONFIDENCE: <float 0.0-1.0>\n\n"
            f"Finding ID: {finding['id']}\n"
            f"Tool: {finding['tool']}\n"
            f"Rule: {finding['rule_id']}\n"
            f"File: {finding['file']}\n"
            f"Lines: {finding['line_start']}-{finding['line_end']}\n"
            f"Severity: {finding['severity']}\n"
            f"CWE: {', '.join(finding.get('cwe_refs', []))}\n"
            f"OWASP: {', '.join(policy.get('owasp', []))}\n"
            f"ASVS: {', '.join(policy.get('asvs', []))}\n"
            f"WSTG: {', '.join(policy.get('wstg', []))}\n"
            f"Remediation refs: {', '.join(finding.get('remediation_refs', []))}\n\n"
            f"Graph context - symbols: {len(evidence_bundle.get('symbol_nodes', []))}\n"
            f"Graph context - statements: {len(evidence_bundle.get('statement_nodes', []))}\n"
            f"Graph context - line window: {len(evidence_bundle.get('line_window', []))}\n"
            f"Graph context - neighbor edges: {len(evidence_bundle.get('neighbor_edges', []))}\n"
        )

    def _build_codebase_analysis_prompt(
        self, graph_stats: dict, findings_summary: dict, file_list: list[str]
    ) -> str:
        return (
            "You are a senior security-focused ML/AI engineer and graph data scientist "
            "producing a professional assessment of a codebase that was analyzed by SPAO "
            "(Security Provenance Automated OWASP), a graph-backed security analysis tool.\n\n"
            "Write a thorough technical analysis covering:\n"
            "1. Executive risk summary\n"
            "2. Graph topology observations (what the code graph reveals about architecture)\n"
            "3. Security posture assessment based on findings\n"
            "4. OWASP mapping quality and coverage\n"
            "5. Recommendations for remediation priority\n"
            "6. Strengths and gaps in the analyzed codebase\n\n"
            "Be specific, cite numbers, and write from the perspective of someone who "
            "understands both graph data science and application security deeply.\n\n"
            f"Graph statistics:\n{json.dumps(graph_stats, indent=2)}\n\n"
            f"Findings summary:\n{json.dumps(findings_summary, indent=2)}\n\n"
            f"Files analyzed ({len(file_list)} total):\n"
            + "\n".join(f"  - {f}" for f in file_list[:100])
            + ("\n  ... and more" if len(file_list) > 100 else "")
        )

    def _parse_analysis_response(self, text: str) -> LLMAnalysis:
        sections = {
            "RISK_NARRATIVE": "",
            "SEVERITY_ASSESSMENT": "",
            "OWASP_COMMENTARY": "",
            "REMEDIATION_GUIDANCE": "",
            "GRAPH_CONTEXT_SUMMARY": "",
            "CONFIDENCE": "0.5",
        }
        current_key = None
        for line in text.split("\n"):
            for key in sections:
                if line.strip().startswith(f"{key}:"):
                    current_key = key
                    sections[key] = line.strip()[len(key) + 1:].strip()
                    break
            else:
                if current_key and current_key != "CONFIDENCE":
                    sections[current_key] += " " + line.strip()

        try:
            confidence = float(sections["CONFIDENCE"].strip())
        except (ValueError, TypeError):
            confidence = 0.5

        return LLMAnalysis(
            risk_narrative=sections["RISK_NARRATIVE"].strip(),
            severity_assessment=sections["SEVERITY_ASSESSMENT"].strip(),
            owasp_commentary=sections["OWASP_COMMENTARY"].strip(),
            remediation_guidance=sections["REMEDIATION_GUIDANCE"].strip(),
            graph_context_summary=sections["GRAPH_CONTEXT_SUMMARY"].strip(),
            confidence=confidence,
        )


class HeuristicPatchProvider(LLMProvider):
    def __init__(self) -> None:
        self.families: list[RemediationFamily] = [
            PythonEvalRemediationFamily(),
            PythonYamlLoadRemediationFamily(),
            JsTsDynamicExecutionRemediationFamily(),
            JsTsTimerStringExecutionRemediationFamily(),
        ]

    def generate_patch(
        self, evidence_bundle: dict[str, object], original_content: str | None = None
    ) -> PatchProposal:
        finding = evidence_bundle["finding"]
        file_path = Path(str(finding["file"]))
        root = Path(str(evidence_bundle["repo_root"]))
        absolute_path = root / file_path
        original = original_content if original_content is not None else absolute_path.read_text(encoding="utf-8")
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
    EVAL_PATTERN = re.compile(r"(?<![A-Za-z0-9_])eval\(")

    def matches(self, finding: dict[str, object]) -> bool:
        rule_id = str(finding["rule_id"]).lower()
        cwe_refs = [str(item).upper() for item in finding.get("cwe_refs", [])]
        file_name = str(finding["file"])
        return file_name.endswith(".py") and ("eval" in rule_id or "CWE-95" in cwe_refs)

    def rewrite_content(self, original: str, finding: dict[str, object]) -> str:
        updated = _replace_on_target_line(
            original,
            int(finding["line_start"]),
            lambda line: self.EVAL_PATTERN.sub("literal_eval(", line, count=1),
        )
        if updated == original:
            updated = self.EVAL_PATTERN.sub("literal_eval(", original, count=1)
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


class PythonYamlLoadRemediationFamily(RemediationFamily):
    family_name = "python_yaml_safe_load"
    YAML_LOAD_PATTERN = re.compile(r"(?<![A-Za-z0-9_])yaml\.load\(")

    def matches(self, finding: dict[str, object]) -> bool:
        rule_id = str(finding["rule_id"]).lower()
        cwe_refs = [str(item).upper() for item in finding.get("cwe_refs", [])]
        file_name = str(finding["file"])
        return file_name.endswith(".py") and (
            "yaml" in rule_id or "deserial" in rule_id or "CWE-502" in cwe_refs
        )

    def rewrite_content(self, original: str, finding: dict[str, object]) -> str:
        updated = _replace_on_target_line(
            original,
            int(finding["line_start"]),
            lambda line: self.YAML_LOAD_PATTERN.sub("yaml.safe_load(", line, count=1),
        )
        if updated == original:
            updated = self.YAML_LOAD_PATTERN.sub("yaml.safe_load(", original, count=1)
        return updated

    def rationale(self, finding: dict[str, object]) -> str:
        return "Replaced yaml.load() with yaml.safe_load() for a bounded unsafe deserialization remediation."


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
        updated = _replace_on_target_line(
            original,
            int(finding["line_start"]),
            lambda line: self.EVAL_PATTERN.sub(self._rewrite_eval_match, line, count=1),
        )
        if updated != original:
            return updated
        updated = _replace_on_target_line(
            original,
            int(finding["line_start"]),
            lambda line: self.FUNCTION_PATTERN.sub(self._rewrite_function_match, line, count=1),
        )
        if updated != original:
            return updated
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


class JsTsTimerStringExecutionRemediationFamily(RemediationFamily):
    family_name = "js_ts_timer_string_callback"
    TIMER_PATTERN = re.compile(
        r"(?P<fn>setTimeout|setInterval)\(\s*(?P<literal>'(?:\\.|[^'])*'|\"(?:\\.|[^\"])*\")(?P<suffix>\s*,.*\))"
    )
    CALL_PATTERN = re.compile(r"(?P<callee>[A-Za-z_$][A-Za-z0-9_$.]*)\(\s*\)\s*;?\s*$")

    def matches(self, finding: dict[str, object]) -> bool:
        rule_id = str(finding["rule_id"]).lower()
        cwe_refs = [str(item).upper() for item in finding.get("cwe_refs", [])]
        file_name = str(finding["file"])
        is_target_language = file_name.endswith(".js") or file_name.endswith(".ts")
        return is_target_language and (
            "settimeout" in rule_id
            or "setinterval" in rule_id
            or "timer" in rule_id
            or ("CWE-95" in cwe_refs and ("timeout" in str(finding["message"]).lower() or "interval" in str(finding["message"]).lower()))
        )

    def rewrite_content(self, original: str, finding: dict[str, object]) -> str:
        updated = _replace_on_target_line(
            original,
            int(finding["line_start"]),
            lambda line: self.TIMER_PATTERN.sub(self._rewrite_timer_match, line, count=1),
        )
        if updated != original:
            return updated
        return self.TIMER_PATTERN.sub(self._rewrite_timer_match, original, count=1)

    def rationale(self, finding: dict[str, object]) -> str:
        return "Replaced string-based JavaScript/TypeScript timer execution with a direct callback wrapper."

    def _rewrite_timer_match(self, match: re.Match[str]) -> str:
        decoded = _decode_js_string_literal(match.group("literal"))
        call_match = self.CALL_PATTERN.fullmatch(decoded.strip())
        if call_match is None:
            return match.group(0)
        callee = call_match.group("callee")
        return f"{match.group('fn')}(() => {callee}(){match.group('suffix')}"


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


def _replace_on_target_line(original: str, line_number: int, replacer) -> str:
    lines = original.splitlines()
    if line_number < 1 or line_number > len(lines):
        return original
    updated_line = replacer(lines[line_number - 1])
    if updated_line == lines[line_number - 1]:
        return original
    lines[line_number - 1] = updated_line
    updated = "\n".join(lines)
    if original.endswith("\n"):
        updated += "\n"
    return updated
