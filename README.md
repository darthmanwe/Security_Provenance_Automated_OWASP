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
- builds deterministic GraphRAG-style fix plans from graph and finding context, preferring Neo4j-backed retrieval when configured
- applies deterministic heuristic remediations for selected Python, JavaScript, and TypeScript rule families when explicitly approved
- records verification and push metadata in the `.spao/` runtime directory

## Sample findings and system behavior

The core design goal is to turn raw findings into auditable, graph-backed remediation evidence instead of jumping straight from "scanner said X" to "LLM changed code."

### Example 1: injection finding with GraphRAG-backed evidence

Using the checked-in [docs/sample-eval.sarif](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/docs/sample-eval.sarif) fixture against [fixtures/python_eval/app.py](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/python_eval/app.py), SPAO normalizes a Semgrep `eval()` finding into one record with:

- scanner rule: `python.lang.security.audit.eval-detected.eval-detected`
- CWE mapping: `CWE-95`
- OWASP mappings: `A03: Injection` plus mobile/API-family context where applicable
- ASVS/WSTG mappings: `asvs-5:V5`, `asvs-5:V10`, `wstg:INPV`
- remediation references: OWASP cheat sheet links

Why GraphRAG matters here:

- the repo is indexed into `File`, `LineSpan`, `Symbol`, and `Statement` nodes before remediation starts
- the fix planner retrieves the local line window, enclosing symbol, nearby statements, and neighbor edges for the exact finding location
- the patch step uses that bounded evidence bundle instead of the whole repository, which makes the behavior more inspectable and easier to trust

GraphRAG is the mechanism that narrows retrieval to the minimum code context needed for a deterministic, reviewable fix plan. 

### Example 2: intake and verification on a real external repo

I used the new `repo pull` capability to pull the public GitHub repo `darthmanwe/Work_Sample` into this workspace:

- clone path: [imports/Work_Sample](C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/imports/Work_Sample)
- detected branch/commit: `main` at `0ebb8aa56a74f362d454c93e2d08b8191f1d8be1`
- auto-initialized SPAO config: [imports/Work_Sample/.spao/config.json](C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/imports/Work_Sample/.spao/config.json)

That repo does not ship a `tests/` folder. Instead of failing with `NO TESTS RAN`, SPAO discovered the best available verification path and executed the notebook workflow:

- chosen strategy: `notebook_execute`
- chosen command: `jupyter nbconvert --to notebook --execute main.ipynb ...`
- verification artifact: [main.verified.ipynb](C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/imports/Work_Sample/.spao/artifacts/main.verified.ipynb)
- verification record: [verify.latest.json](C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/imports/Work_Sample/.spao/verify.latest.json)

Operational significance:

- the intake path can onboard an unfamiliar public repo automatically
- verification is capability-aware rather than hardcoded to one repository layout
- the current boundary is explicit: GraphRAG ingestion is strongest on Python/JS/TS source repos, while notebook-heavy repos are currently better served by adaptive verification than by code graph extraction alone

### Engineering takeaways

- security engineering: findings are normalized into OWASP/CWE/ASVS/WSTG language instead of left as tool-specific noise
- retrieval design: graph-backed local context is used to make remediation narrower and more explainable
- automation quality: the workflow now handles public repo intake, idempotent re-runs, and repos without a `tests/` folder
- capability adaptation: when the imported repo did not match the original assumption set, the verifier was extended to discover a sensible strategy instead of forcing every repo into one template

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
- `fixtures/`: intentionally vulnerable sample projects for local demos and scanner experiments
- `docs/`: reproducible walkthroughs and sample SARIF inputs

## Setup

### Requirements

- Python 3.12+
- Git
- optional local tools for richer analysis:
  - `semgrep`
  - `ruff`
  - `bandit`
  - `eslint`
  - `neo4j` server access is optional if you want direct graph persistence during ingest
  - `node` is required for the parser-backed JavaScript and TypeScript indexing path

### Install

```bash
python -m pip install -e .
```

Or run directly from the repo:

```bash
python -m spao --help
```

## Workspace intake

To pull a public GitHub repo into the current workspace and make it SPAO-ready:

```bash
python -m spao repo pull https://github.com/<owner>/<repo>
```

This clones or updates the repo under `imports/<repo>` in the current working directory and ensures the imported repo contains `.spao/config.json`.

You can override the destination as long as it stays inside the current workspace:

```bash
python -m spao repo pull https://github.com/<owner>/<repo> --dest imports/custom-repo
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

Optional direct Neo4j persistence:

```bash
python -m spao ingest --persist-neo4j
```

Inspect the graph artifact with deterministic helpers:

```bash
python -m spao graph query --kind symbols --path fixtures/javascript_eval/app.js --line-start 1
```

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
- nearby statements and graph edges
- sibling findings in the same file
- OWASP, ASVS, and WSTG references
- remediation links
- recommended next actions

If `.spao/config.json` points to Neo4j and the configured password environment variable is set, fix planning retrieves evidence from Neo4j first and falls back to the JSON graph artifact otherwise.

To include grouped file sections in the plan:

```bash
python -m spao fix plan <finding-id> --group-by file
```

### 6. Apply a lightweight approved patch

```bash
python -m spao fix apply <finding-id> --approve
```

Current auto-remediation support:

- Python `eval()` misuse with `CWE-95` or matching `eval` rule IDs
- Python `yaml.load(...)` unsafe deserialization findings that can be rewritten to `yaml.safe_load(...)`
- JavaScript and TypeScript literal `eval(...)` misuse that can be rewritten to `JSON.parse(...)`
- JavaScript and TypeScript literal `new Function(...)()` misuse with JSON-safe return bodies
- JavaScript and TypeScript string-based `setTimeout(...)` and `setInterval(...)` callbacks that can be rewritten to direct callback wrappers

Grouped approval workflow:

```bash
python -m spao approvals list
python -m spao approvals approve <section-id>
python -m spao fix apply <section-id> --approve
```

Artifacts written:

- `.spao/patches/<finding>.diff`
- `.spao/patches/<finding>.json`

### 7. Verify

```bash
python -m spao verify
```

This runs:

```bash
python -m spao verify
```

And writes:

- `.spao/verify.latest.json`

Verification discovers the best available repo-local validation command in this order:

- `python -m unittest discover -s tests -v` when a `tests/` directory exists
- `npm test` when a repo ships a non-placeholder Node test script
- `python -m pytest -q` or `python -m unittest discover -v` for Python repos with test files but no `tests/` directory
- `jupyter nbconvert --execute ...` for notebook-centric repos with no conventional test layout

Verification records a section-aware summary, includes the discovered command and strategy in `.spao/verify.latest.json`, and upgrades patched sections to verified status when the chosen validation run passes.

### 8. Push and record push metadata

```bash
python -m spao push
```

This pushes the current branch and writes:

- `.spao/push.latest.json`

Push is gated when any approved or applied section has not yet passed verification.

## Current OWASP policy model

This PoC does not pretend OWASP publishes one single universal "full vulnerability list." Instead, it uses a layered policy model:

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

The "GraphRAG" part of this repo is intentionally deterministic:

- the graph is built from the codebase first
- findings are detected by scanners, not invented by the model
- evidence bundles are assembled from graph context and policy mappings
- patch generation consumes the evidence bundle rather than the whole repo

This keeps the remediation pipeline inspectable and easier to trust during early experimentation.

## Limitations

- Neo4j-backed fix planning depends on local driver availability, a reachable server, and persisted graph data; the planner falls back to JSON when that path is unavailable
- scanner execution beyond SARIF import is intentionally shallow
- automatic remediation remains intentionally narrow and only supports deterministic low-ambiguity rewrite families
- push behavior depends on local git authentication and remote access
- policy packs are curated snapshots, not full upstream mirrors

## Fixtures

The repo includes intentionally vulnerable starter fixtures:

- [fixtures/python_eval/app.py](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/python_eval/app.py)
- [fixtures/javascript_eval/app.js](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/javascript_eval/app.js)
- [fixtures/typescript_authz/app.ts](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/fixtures/typescript_authz/app.ts)

These are meant for local scanning, graph inspection, and future demo runs.

## Example walkthrough

See [docs/sample-session.md](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/docs/sample-session.md) for a concrete repo-local walkthrough that uses [docs/sample-eval.sarif](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/docs/sample-eval.sarif) and the checked-in vulnerable fixtures.

Walkthrough smoke test on April 16, 2026:

- `graph query` returned the expected `run` symbol for `fixtures/python_eval/app.py`
- `analyze --sarif docs/sample-eval.sarif` produced `1` normalized finding
- `fix plan` generated a single-target evidence bundle under `.spao/fixplans/`

## Test suite

Run:

```bash
python -m unittest discover -s tests -v
```

Latest local run on April 16, 2026:

- `31/31` tests passing
- completed in about `10s`
- exercises `repo pull`, `init`, `ingest`, `analyze`, `graph query`, `fix plan`, `fix apply`, `approvals`, `verify`, and `push`

Highlighted behaviors covered by the suite:

- public GitHub workspace intake with managed `imports/` destinations, idempotent update behavior, and destination safety checks
- verification command discovery for repos without a `tests/` directory, including notebook fallback
- parser-backed graph indexing across Python, JavaScript, and TypeScript symbols and statements
- SARIF normalization with CWE, OWASP Top 10, ASVS, WSTG, and remediation-link enrichment
- Neo4j persistence and retrieval contracts for graph-backed fix planning
- grouped approval sections and atomic multi-finding apply flows
- deterministic remediations for Python `eval`, Python `yaml.load`, JS literal `eval`, JS literal `new Function`, and TS string timer callbacks
- safe refusal when a JavaScript `eval(...)` target is ambiguous
- verification summaries that upgrade section state only after tests pass
- push gating that blocks branch publication until approved or applied sections have been verified

If you want a quick proof run without supplying your own scanner output, the documented walkthrough in [docs/sample-session.md](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/docs/sample-session.md) uses the committed [docs/sample-eval.sarif](/C:/Users/darth/OneDrive/Belgeler/GitHub/Security_Provenance_Automated_OWASP/docs/sample-eval.sarif) fixture.

## Suggested next build steps

- add Fortify SCA import into the normalized finding schema
- add richer Neo4j-backed retrieval into fix planning instead of JSON-first graph lookups
- expand automatic remediation into additional Python, JS, and TS rule families
- add section-aware verification summaries and push gating
