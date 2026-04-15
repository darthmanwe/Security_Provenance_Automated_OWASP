# Sample SPAO Session

This walkthrough shows the expected operator flow for the current proof of concept.

## 1. Initialize

```bash
python -m spao init --project-name demo
```

Expected result:
- `.spao/config.json` created

## 2. Index the repo

```bash
python -m spao ingest
```

Expected result:
- `.spao/graph.latest.json` created
- metadata includes indexed file, line, symbol, and statement counts

## 3. Import scanner findings

```bash
python -m spao analyze --sarif fixture.sarif
```

Expected result:
- `.spao/findings.latest.json` created
- findings enriched with CWE and OWASP references

## 4. Review findings

```bash
python -m spao findings list
```

Expected result:
- structured JSON output showing normalized findings and metadata

## 5. Build a fix plan

```bash
python -m spao fix plan <finding-id>
```

Expected result:
- `.spao/fixplans/<finding>.json`
- line window
- symbol context
- sibling findings
- remediation references

## 6. Apply an approved patch

```bash
python -m spao fix apply <finding-id> --approve
```

Expected result:
- source file updated
- `.spao/patches/<finding>.diff`
- normalized finding state updated to `patch_applied`

## 7. Verify

```bash
python -m spao verify
```

Expected result:
- `.spao/verify.latest.json`
- findings updated with verification state

## 8. Push

```bash
python -m spao push
```

Expected result:
- current branch pushed
- `.spao/push.latest.json`
- findings updated with push state
