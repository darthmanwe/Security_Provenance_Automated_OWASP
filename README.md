# Security Provenance Automated OWASP

`spao` is a proof-of-concept CLI for indexing source code into a graph, mapping scanner findings to OWASP-aligned policy catalogs, and preparing human-reviewed code fixes with a lightweight GitHub workflow.

## Current status

Step 1 is in place:
- Python package scaffold
- CLI shell and config bootstrap
- Git workflow helpers for branch, commit, and push operations
- `spao init` for local project setup

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

## Supported languages

The PoC targets:
- Python
- JavaScript
- TypeScript

## Step notes

This first step focuses on repository foundation only. Graph indexing, finding ingestion, and fix generation land in the next milestones.

## Next step

Implement repo ingestion, graph indexing, and the initial code graph schema.
