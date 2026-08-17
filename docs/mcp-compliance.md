# MCP conformance

Produced by the official conformance suite, [modelcontextprotocol/conformance](https://github.com/modelcontextprotocol/conformance), run against this server over loopback HTTP. Each check is pass or fail; the run is gated on a committed baseline of expected failures.

| | |
|---|---|
| Server version | `dev` |
| Commit | `ca5a2b1c602fffac9faac45afcc199b56c9bd878` |
| Generated | `2026-08-17T06:33:52Z` |
| Workflow run | https://github.com/deploymenttheory/windows-mcp-server/actions/runs/32001989428 |

## Summary

| Pass | Spec | Harness | Passed | Failed | Warned | Skipped |
|---|---|---|---:|---:|---:|---:|
| product | `2026-07-28` | `0.2.0-alpha.10` | 59 | 34 | 2 | 2 |
| fixtures | `2026-07-28` | `0.2.0-alpha.10` | 113 | 0 | 0 | 2 |

## Pass: product

Run against the manifest this server actually ships. Scenarios needing the suite's named fixtures cannot execute here and are listed in the baseline; what this pass covers is the transport and wire conformance that the 2026-07-28 revision is about.

Gated against `conformance/baseline-product.yml`; a failure not listed there fails the build, and so does an entry there that has started passing.

| Check | Problem |
|---|---|
| `json-schema-2020-12-tool-found` | Tool 'json_schema_2020_12_tool' not found. Available tools: App, Apply, Assert, CaptureEvidence, Click, Clipboard, Credentials, DisplayInventory, EventLog, FileSystem, GetText, GuardrailStatus, Invoke, Kill, LaunchExecutable, Move, MultiEdit, MultiSelect, Network, Notification, Package, Plan, PowerS… |
| `prompts-get-embedded-resource` | Failed: unknown prompt "test_prompt_with_embedded_resource" |
| `prompts-get-simple` | Failed: unknown prompt "test_simple_prompt" |
| `prompts-get-with-args` | Failed: unknown prompt "test_prompt_with_arguments" |
| `prompts-get-with-image` | Failed: unknown prompt "test_prompt_with_image" |
| `resources-read-binary` | Failed: Resource not found |
| `resources-read-text` | Failed: Resource not found |
| `resources-templates-read` | Failed: Resource not found |
| `sep-2243-server-decode-base64` | Not testable: server exposes no tool with x-mcp-header annotations |
| `sep-2243-server-no-xmcp-tool` | Not testable: server exposes no tool with x-mcp-header annotations, so none of the custom-header validation requirements could be exercised |
| `sep-2243-server-reject-invalid-param-chars` | Not testable: server exposes no tool with x-mcp-header annotations |
| `sep-2243-server-reject-param-mismatch` | Not testable: server exposes no tool with x-mcp-header annotations |
| `sep-2243-server-validate-param-match` | Not testable: server exposes no tool with x-mcp-header annotations |
| `sep-2322-elicitation-incomplete` | JSON-RPC error: unknown tool "test_input_required_result_elicitation" |
| `sep-2322-list-roots-incomplete` | JSON-RPC error: unknown tool "test_input_required_result_list_roots" |
| `sep-2322-multi-round-r1` | Expected InputRequiredResult with inputRequests and requestState |
| `sep-2322-multiple-inputs-incomplete` | JSON-RPC error: unknown tool "test_input_required_result_multiple_inputs" |
| `sep-2322-non-tool-incomplete` | JSON-RPC error: unknown prompt "test_input_required_result_prompt" |
| `sep-2322-reject-tampered-state` | Prerequisite failed: could not get initial InputRequiredResult with requestState |
| `sep-2322-request-state-incomplete` | JSON-RPC error: unknown tool "test_input_required_result_request_state" |
| `sep-2322-respect-client-capabilities` | JSON-RPC error: unknown tool "test_input_required_result_capabilities" |
| `sep-2322-result-type-included` | JSON-RPC error: unknown tool "test_input_required_result_elicitation" |
| `sep-2322-sampling-incomplete` | JSON-RPC error: unknown tool "test_input_required_result_sampling" |
| `sep-2575-http-server-no-independent-requests-on-stream` | Not testable: server does not list the diagnostic tool 'test_streaming_elicitation' in tools/list, so the response stream could not be exercised |
| `sep-2575-missing-capability-http-400` | Not testable: server does not list the diagnostic tool 'test_missing_capability' in tools/list, so the -32021 HTTP status could not be validated |
| `sep-2575-server-no-log-without-loglevel` | Not testable: server does not list the diagnostic tool 'test_logging_tool' in tools/list, so the no-log-without-logLevel requirement could not be exercised |
| `sep-2575-server-rejects-undeclared-capability` | Not testable: server does not list the diagnostic tool 'test_missing_capability' in tools/list and the probe call did not exercise it (required for the undeclared-capability rejection) |
| `tools-call-audio` | Failed: unknown tool "test_audio_content" |
| `tools-call-embedded-resource` | Failed: unknown tool "test_embedded_resource" |
| `tools-call-error` | Failed: unknown tool "test_error_handling" |
| `tools-call-image` | Failed: unknown tool "test_image_content" |
| `tools-call-mixed-content` | Failed: unknown tool "test_multiple_content_types" |
| `tools-call-simple-text` | Failed: unknown tool "test_simple_text" |
| `tools-call-with-progress` | Failed: unknown tool "test_tool_with_progress" |

## Pass: fixtures

Run with the suite's fixture tools, resources and prompts registered, so tools/call, resources/read, resources/templates/list and prompts/get are exercised through the real middleware and result constructors. The fixtures exist only under the `conformance` build tag and are never present in a released binary.

Gated against `conformance/baseline-fixtures.yml`; a failure not listed there fails the build, and so does an entry there that has started passing.

No unexpected failures across 115 checks.
