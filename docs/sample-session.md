# Sample SPAO Session

This walkthrough uses the checked-in fixture code and a committed SARIF sample so the flow is reproducible from a fresh clone of this repository.

## Scenario

- target file: `fixtures/python_eval/app.py`
- finding source: `docs/sample-eval.sarif`
- goal: index the repo, normalize one injected scanner result, inspect the evidence bundle, and optionally apply a deterministic patch

## 1. Initialize the local runtime

```bash
python -m spao init --project-name Security_Provenance_Automated_OWASP
```

Expected result:

- `.spao/config.json` is created
- the JSON response includes `config_path` and the current `branch`

## 2. Index the repository

```bash
python -m spao ingest
```

Expected result:

- `.spao/graph.latest.json` is created
- graph metadata reports indexed file, line, symbol, and statement counts
- Git-tracked Python, JavaScript, and TypeScript files are represented as `File`, `LineSpan`, `Symbol`, and `Statement` nodes

Optional inspection:

```bash
python -m spao graph query --kind symbols --path fixtures/python_eval/app.py --line-start 1
```

Expected result:

- JSON output with the `run` symbol from the vulnerable Python fixture

## 3. Import a concrete SARIF finding

```bash
python -m spao analyze --sarif docs/sample-eval.sarif
```

Expected result:

- `.spao/findings.latest.json` is created
- the response summary reports `total: 1`
- the imported finding is enriched with `CWE-95`, OWASP Top 10 injection mapping, ASVS references, WSTG references, and remediation links

## 4. Review the normalized finding

```bash
python -m spao findings list
```

Expected result:

- JSON output containing one finding for `fixtures/python_eval/app.py`
- the finding includes a stable `id`, severity, policy mappings, and approval / verification state fields

Copy the `id` from that output for the next steps.

## 5. Build a deterministic fix plan

```bash
python -m spao fix plan <finding-id>
```

Expected result:

- `.spao/fixplans/<finding-id>.json` is created
- the plan includes:
  - the original finding payload
  - a nearby line window
  - enclosing symbol context
  - nearby statement nodes and graph edges
  - recommended next actions
- the planner reports `retrieval_backend: "json"` unless you configured Neo4j persistence

## 6. Optionally apply the supported patch

This step edits `fixtures/python_eval/app.py`, so run it on a throwaway branch if you want to keep the fixture unchanged.

```bash
python -m spao fix apply <finding-id> --approve
```

Expected result:

- `eval(user_input)` is rewritten to `literal_eval(user_input)`
- `from ast import literal_eval` is inserted if needed
- `.spao/patches/<finding-id>.diff` and `.spao/patches/<finding-id>.json` are created
- the response reports `remediation_family: "python_eval_literal_eval"`

## 7. Verify the workspace

```bash
python -m spao verify
```

Expected result:

- `.spao/verify.latest.json` is created
- the verification payload includes `passed`, `command`, and `section_summary`
- patched findings advance to a verified state when the test run passes

## 8. Push only after verification passes

```bash
python -m spao push
```

Expected result:

- `.spao/push.latest.json` is created on success
- push is blocked if any approved or applied section still needs verification

## Artifact flow

The walkthrough produces this runtime sequence under `.spao/`:

1. `config.json`
2. `graph.latest.json`
3. `findings.latest.json`
4. `fixplans/<finding-id>.json`
5. `patches/<finding-id>.diff` and `patches/<finding-id>.json` after apply
6. `verify.latest.json`
7. `push.latest.json`

## What this demonstrates

- parser-backed graph indexing for Python, JavaScript, and TypeScript
- SARIF normalization into a single OWASP-aware finding model
- deterministic evidence bundle generation for fix planning
- bounded auto-remediation for supported rule families
- verification-aware push gating
