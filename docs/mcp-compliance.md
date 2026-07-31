# MCP conformance

> **This file is generated.** `.github/workflows/mcp-spec-compliance.yml` runs the
> official conformance suite against the server and overwrites this file with the
> result. Do not edit it by hand.

No run has been recorded yet. The next scheduled run, or one started on demand via
**Actions → mcp | Spec Compliance → Run workflow**, replaces this page with:

- per-scenario pass/fail for the **product** pass, run against the manifest the
  server ships;
- per-scenario pass/fail for the **fixtures** pass, run with the suite's named
  fixture tools registered so `tools/call`, `resources/read` and `prompts/get` are
  exercised;
- the suite version, protocol revision, commit and workflow run behind the result.

Raw `checks.json` output is committed alongside it under `conformance/results/`, so
the evidence is readable without re-running anything.

To run it locally:

```powershell
go build -tags conformance -o conformance-host.exe ./cmd/windows-mcp-server
./conformance-host.exe conformance-serve --addr 127.0.0.1:3001            # product pass
./conformance-host.exe conformance-serve --addr 127.0.0.1:3002 --fixtures # fixtures pass

npx -y @modelcontextprotocol/conformance@0.2.0-alpha.10 server `
  --url http://127.0.0.1:3001/mcp --suite all --spec-version 2026-07-28 `
  --expected-failures conformance/baseline-product.yml
```

`--suite all` is required: the suite classifies `2026-07-28` as its draft revision,
so `--suite active` excludes the scenarios that revision introduced.
