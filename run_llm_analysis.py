"""Run the LLM-powered analysis on the lorekeeper import and save results."""
import json
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

os.environ.pop("NEO4J_PASSWORD", None)

sys.path.insert(0, str(Path(__file__).parent))

from spao.llm.analyzer import run_full_llm_report

root = Path(__file__).parent / "imports" / "lorekeeper"
print(f"Running LLM analysis on: {root}")
print(f"API key present: {bool(os.environ.get('ANTHROPIC_API_KEY'))}")

report = run_full_llm_report(root)

output_path = root / ".spao" / "llm_analysis.json"
output_path.write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
print(f"\nSaved to: {output_path}")
print(f"\nGraph stats: {json.dumps(report['graph_stats'], indent=2)}")
print(f"\nFindings summary total: {report['findings_summary']['total']}")
print(f"Finding analyses count: {len(report['finding_analyses'])}")
print(f"\nLLM narrative length: {len(report['llm_narrative'])} chars")
print(f"\nFirst 2000 chars of LLM narrative:")
print(report['llm_narrative'][:2000])
