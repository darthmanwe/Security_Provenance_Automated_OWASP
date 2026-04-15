# Security Provenance Automated OWASP

`spao` is a proof-of-concept CLI for indexing source code into a graph, mapping scanner findings to OWASP-aligned policy catalogs, and preparing human-reviewed code fixes with a lightweight GitHub workflow.

## Current status

Step 2 is in place:
- Python package scaffold
- CLI shell and config bootstrap
- Git workflow helpers for branch, commit, and push operations
- `spao init` for local project setup
- `spao ingest` for graph indexing into a local artifact
- code graph schema with repo, snapshot, file, line, symbol, and statement nodes

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

## Supported languages

The PoC targets:
- Python
- JavaScript
- TypeScript

## Step notes

The current implementation focuses on repository foundation and graph indexing. Scanner ingestion, OWASP taxonomy loading, and fix generation land in the next milestones.

## Next step

Implement scanner adapters, SARIF normalization, and the first normalized findings workflow.
