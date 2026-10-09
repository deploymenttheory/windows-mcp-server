# MCP spec gate

The required `MCP spec gate` PR check validates the MCP behavior this server implements against the **latest published** protocol schema. It runs on every PR, even when a PR changes no protocol files.

The gate captures the real product server over an in-memory SDK transport and validates the raw client-visible responses. It checks discovery and advertised capabilities, tool, prompt, resource and resource-template lists, every advertised definition, embedded tool argument and result schemas, and safe live calls to `Wait`, each listed prompt, and completion. Separate wire tests cover the shared text, image, error, and resource result constructors. A response or definition that violates the current schema fails the check. A capability without a validator also fails, so newly added features must gain coverage.

The workflow queries the upstream [published MCP schema revisions](https://github.com/modelcontextprotocol/modelcontextprotocol/tree/main/schema) on every PR. If the vendored revision is older, or the query fails, the check fails. Updating `schema/versions.json` and the vendored `schema.json` then requires assessing the implemented methods against that revision. The current latest published revision is `2026-07-28`.

Run the same product checks locally:

```sh
go test ./internal/winmcp ./pkg/windows -run 'TestProductSpecGate|TestProductResultShapesMatchLatestSpec|TestServedSurfaceValidatesAgainstTheNewestRevision' -count=1
```

This gate tests implemented behavior; it does not claim support for every optional MCP feature. Runtime actions that need an interactive desktop are exercised by platform acceptance tests rather than CI's headless product probes. The optional HTTP conformance host remains behind the `conformance` build tag for manual diagnostics; its named fixtures are not part of the shipped product or the required PR verdict.
