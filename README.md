# Security Provenance Automated OWASP

`spao` is a proof-of-concept CLI that indexes source code into a local graph artifact, normalizes scanner findings into a layered OWASP-aware model, builds deterministic evidence bundles for remediation, and applies lightweight human-approved fixes for supported cases.

## What this PoC does

- indexes Git-tracked Python, JavaScript, and TypeScript files into a graph-shaped JSON artifact
- keeps line-level provenance while also capturing symbols and statements
- imports SARIF results and normalizes findings into one schema
- enriches findings using:
  - OWASP Top 10
  - OWASP API Security Top 10:2023
  - OWASP Mobile Top 10:2024
  - OWASP ASVS 5 family mappings
  - OWASP WSTG family mappings
  - OWASP Cheat Sheet remediation links
  - CWE crosswalks
- builds deterministic GraphRAG-style fix plans from graph and finding context
- applies a first heuristic remediation for unsafe Python `eval()` usage when explicitly approved
- records verification and push metadata in the `.spao/` runtime directory

## Repository layout

- `spao/cli.py`: CLI entrypoint
- `spao/config.py`: local project config helpers
- `spao/graph/`: graph schema and JSON persistence
- `spao/indexer/`: code indexing and graph construction
- `spao/sarif/`: normalized finding model and SARIF parsing
- `spao/scanners/`: scanner adapter shell
- `spao/policy/`: layered OWASP/CWE policy packs and enrichment logic
- `spao/triage/`: finding summaries
- `spao/fix/`: evidence bundle generation, provider contract, and patch application
- `spao/approval/`: lightweight approval helpers
- `spao/gitops/`: git-aware push tracking
- `spao/verify/`: verification workflow
- `tests/`: end-to-end CLI and workflow tests
- `fixtures/`: intentionally vulnerable sample projects for future demos and scanner experiments
- `docs/`: sample command transcript and onboarding notes

## Setup

### Requirements

- Python 3.12+
- Git
- optional local tools for richer analysis:
  - `semgrep`
  - `ruff`
  - `bandit`
  - `eslint`
  - Neo4j is planned as the graph backend target, but this PoC currently persists a local graph artifact first

### Install

```bash
python -m pip install -e .
```

Or run directly from the repo:

```bash
python -m spao --help
```

## CLI workflow

### 1. Initialize local runtime config

```bash
python -m spao init --project-name Security_Provenance_Automated_OWASP
```

This creates `.spao/config.json`.

### 2. Index the codebase

```bash
python -m spao ingest
```

This writes `.spao/graph.latest.json` with:
- `Repo`
- `Snapshot`
- `File`
- `LineSpan`
- `Symbol`
- `Statement`

Key edges:
- `CONTAINS`
- `HAS_LINE`
- `DECLARES`
- `AST_PARENT`
- `NEXT_LINE`

### 3. Normalize scanner findings

Use local SARIF:

```bash
python -m spao analyze --sarif path/to/results.sarif
```

Or let the tool attempt locally installed scanners:

```bash
python -m spao analyze
```

This writes `.spao/findings.latest.json`.

### 4. Inspect normalized findings

```bash
python -m spao findings list
```

### 5. Build a deterministic fix plan

```bash
python -m spao fix plan <finding-id>
```

This writes `.spao/fixplans/<finding>.json` with:
- the original finding
- nearby line window
- enclosing symbols
- sibling findings in the same file
- OWASP, ASVS, and WSTG references
- remediation links
- recommended next actions

### 6. Apply a lightweight approved patch

```bash
python -m spao fix apply <finding-id> --approve
```

Current auto-remediation support:
- Python `eval()` misuse with `CWE-95` or matching `eval` rule IDs

Artifacts written:
- `.spao/patches/<finding>.diff`
- `.spao/patches/<finding>.json`

### 7. Verify

```bash
python -m spao verify
```

This runs:

```bash
python -m unittest discover -s tests -v
```

And writes:
- `.spao/verify.latest.json`

### 8. Push and record push metadata

```bash
python -m spao push
```

This pushes the current branch and writes:
- `.spao/push.latest.json`

## Current OWASP policy model

This PoC does not pretend OWASP publishes one single universal “full vulnerability list.” Instead, it uses a layered policy model:

- web risk categories from OWASP Top 10
- API risk categories from OWASP API Security Top 10:2023
- mobile risk categories from OWASP Mobile Top 10:2024
- ASVS 5 section families for control-oriented classification
- WSTG testing families for test-oriented classification
- Cheat Sheet links for remediation guidance
- CWE IDs as the shared normalization key

That means the tool can translate one finding into multiple useful views:
- scanner rule
- CWE
- OWASP risk category
- ASVS control family
- WSTG testing family
- remediation guide

## GraphRAG approach in this PoC

The “GraphRAG” part of this repo is intentionally deterministic:

- the graph is built from the codebase first
- findings are detected by scanners, not invented by the model
- evidence bundles are assembled from graph context and policy mappings
- patch generation consumes the evidence bundle rather than the whole repo

This keeps the remediation pipeline inspectable and easier to trust during early experimentation.

## Limitations

- graph storage is local JSON first; direct Neo4j persistence is not implemented yet
- JavaScript and TypeScript parsing is lightweight and regex-driven in this PoC
- scanner execution beyond SARIF import is intentionally shallow
- only one heuristic auto-fix family is implemented today
- push behavior depends on local git authentication and remote access
- policy packs are curated snapshots, not full upstream mirrors

## Fixtures

The repo includes intentionally vulnerable starter fixtures:

- [fixtures/python_eval/app.py](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/python_eval/app.py)
- [fixtures/javascript_eval/app.js](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/javascript_eval/app.js)
- [fixtures/typescript_authz/app.ts](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/typescript_authz/app.ts)

These are meant for local scanning, graph inspection, and future demo runs.

## Example walkthrough

See [docs/sample-session.md](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/docs/sample-session.md) for a concrete sequence of commands and the expected artifact flow.

## Test suite

Run:

```bash
python -m unittest discover -s tests -v
```

Current coverage includes:
- `init`
- `ingest`
- `analyze`
- `fix plan`
- `fix apply`
- `verify`

## Suggested next build steps

- add direct Neo4j persistence and query helpers
- deepen JS/TS parsing with a real parser layer
- expand automatic remediation beyond the initial heuristic family
- add richer grouped approvals and multi-finding sections
- add Fortify SCA import into the normalized finding schema
