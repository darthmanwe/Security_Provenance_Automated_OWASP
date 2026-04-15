# Security Provenance Automated OWASP

`spao` is a proof-of-concept CLI for indexing source code into a graph, mapping scanner findings to OWASP-aligned policy catalogs, and preparing human-reviewed code fixes with a lightweight GitHub workflow.

## Current status

Step 4 is in place:
- Python package scaffold
- CLI shell and config bootstrap
- Git workflow helpers for branch, commit, and push operations
- `spao init` for local project setup
- `spao ingest` for graph indexing into a local artifact
- code graph schema with repo, snapshot, file, line, symbol, and statement nodes
- `spao analyze` for SARIF-backed finding normalization
- `spao findings list` for reading the current normalized finding set
- layered OWASP, ASVS, WSTG, and Cheat Sheet policy catalogs
- CWE-driven policy enrichment for normalized findings

## Planned commands

- `spao init`
- `spao ingest`
- `spao analyze`
- `spao findings list`
- `spao fix plan <finding-or-section>`
- `spao fix apply <finding-or-section> --approve`
- `spao verify`
- `spao push`

## Architecture stub

The project is split into modules for:
- CLI orchestration
- graph storage and querying
- code indexing
- SARIF ingestion
- scanner adapters
- OWASP and CWE policy catalogs
- fix planning and application
- lightweight approval and git workflow tracking

## Graph indexing

`spao ingest` currently:
- enumerates Git-tracked `.py`, `.js`, and `.ts` files
- excludes dependency, build, and virtualenv-style directories
- builds a local graph artifact at `.spao/graph.latest.json`
- emits nodes for `Repo`, `Snapshot`, `File`, `LineSpan`, `Symbol`, and `Statement`
- emits edges for `CONTAINS`, `HAS_LINE`, `DECLARES`, `AST_PARENT`, and `NEXT_LINE`

This keeps line-level provenance while still giving findings a semantic owner beyond raw line numbers.

## Finding normalization

`spao analyze` currently supports:
- importing one or more SARIF files via `--sarif`
- attempting local scanner execution where tools are installed
- normalizing findings into `.spao/findings.latest.json`
- preserving canonical fields for severity, location, CWE tags, OWASP tags, and workflow state

`spao findings list` reads the latest normalized artifact and prints the structured result for downstream policy enrichment and fix planning.

## Policy coverage

The PoC now ships curated policy packs for:
- OWASP Top 10 (web)
- OWASP API Security Top 10:2023
- OWASP Mobile Top 10:2024
- OWASP ASVS 5 section families
- OWASP WSTG stable testing families
- OWASP Cheat Sheet remediation links

Findings are enriched by:
- direct OWASP aliases already present in scanner tags
- CWE crosswalks that map findings into OWASP, ASVS, and WSTG references
- remediation links derived from the Cheat Sheet catalog

## Supported languages

The PoC targets:
- Python
- JavaScript
- TypeScript

## Step notes

The current implementation now includes repository foundation, graph indexing, SARIF-backed finding normalization, and layered OWASP taxonomy enrichment. Fix planning and patch generation land in the next milestones.

## Next step

Implement deterministic graph retrieval and the first fix planning workflow.
