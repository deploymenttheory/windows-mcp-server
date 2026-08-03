# Journeys as code

A **journey** is a named sequence of UI actions, each with assertions about the
resulting screen and evidence to capture — a user journey (a login smoke test, a
UI regression) written as JSON and run deterministically, rather than as a prose
script a human follows by hand.

A journey **compiles to a [plan](plan-and-apply.md)** and runs through the same
executor `Apply` uses: every step is evaluated by the policy engine, audited as a
`plan.step`, and **fail-stopped** on the first failure. An assertion compiles to a
call of the `Assert` or `WaitFor` tool, so a failed assertion is a failed step —
the run stops there and reports it, exactly as a test runner would.

## The document

```json
{
  "version": 1,
  "name": "notepad-smoke",
  "description": "Open Notepad, type a line, and verify it appears.",
  "steps": [
    {
      "name": "open Notepad",
      "tool": "App",
      "args": { "name": "notepad" },
      "assertions": [ { "kind": "wait_window_active", "target": "Notepad", "timeout": 15 } ],
      "evidence": [ "notepad opened" ]
    },
    {
      "name": "type a line",
      "tool": "Type",
      "args": { "text": "hello" },
      "assertions": [ { "kind": "text_present", "target": "hello" } ]
    }
  ],
  "expected_evidence": [ "notepad opened" ]
}
```

- **`steps[].tool` / `args`** — the action: any served inventory tool and its
  arguments, the same shape a plan step carries.
- **`steps[].assertions`** — conditions checked *after* the action. A failing one
  fails the step and stops the journey.
- **`steps[].evidence`** — captions for screenshots to capture at that point (each
  compiles to a `CaptureEvidence` call).
- **`expected_evidence`** — labels a passing run must produce; every entry must be
  captured by some step, or validation rejects the file.

Unknown fields are rejected, so a typo in a key fails at `validate` rather than
being silently ignored.

## Assertion kinds

Two symmetric families. An **immediate** kind checks the screen once; a **polled**
kind (`wait_…`) waits for that same condition to hold, up to `timeout` seconds. A
polled kind's name is its immediate twin with a `wait_` prefix — the one exception
is `text_absent`, which has no polled form, since you cannot wait for a thing to
not be there.

| `kind` | Compiles to | Passes when |
|---|---|---|
| `text_present` | `Assert text_present` | the UI-tree text contains `target` |
| `text_absent` | `Assert text_absent` | the UI-tree text does **not** contain `target` |
| `element_present` | `Assert element_present` | an interactive element's name contains `target` |
| `window_active` | `Assert window_active` | the foreground window title contains `target` |
| `wait_text_present` | `WaitFor text_exists` | the text appears within `timeout` seconds |
| `wait_element_present` | `WaitFor element_exists` | the element appears within `timeout` |
| `wait_window_active` | `WaitFor active_window` | the window becomes active within `timeout` |

`timeout` (seconds) is only meaningful for the `wait_…` kinds; setting it on an
immediate kind is a validation error. Every kind needs a `target`.

## Running

```powershell
# Offline — parse, validate, and compile to a plan. No desktop needed; put it in CI.
windows-mcp-server journey validate journeys/examples/notepad-smoke.json

# Live — run against the real desktop and report pass/fail. Exits 1 on failure.
windows-mcp-server journey run journeys/examples/notepad-smoke.json --policy-config policy.json
windows-mcp-server journey run journeys/examples/notepad-smoke.json --json   # for CI
```

`run` requires an interactive desktop; on a machine that cannot host UI automation
it errors rather than reporting a spurious pass. The whole run is recorded in the
audit chain — a `journey.started` at the start, a `plan.step` per action and
assertion, and a `journey.finished` with the pass/fail counts — so the same audit
directory can later be sealed into an [evidence bundle](../docs/security-architecture.md).

The testing toolset (`Assert`, `WaitFor`, `CaptureEvidence`) is served
automatically for a journey run, so a journey's assertions work regardless of the
rest of the toolset selection.

## Relationship to plans

A journey **is** a pre-authored plan plus interleaved assertions and evidence. That
means it inherits every property of plan-and-apply: whole-plan adjudication before
anything runs, per-step live policy evaluation at execution, fail-stop atomicity,
and abandonment on a kill-switch trip. A journey step that hits a policy `deny`
(or an unapproved `approve`) refuses and stops the run, the same as any plan step.

## Not yet covered

- **`result_contains`** — asserting on a step's *own* tool result (e.g. what
  `GetText` returned) rather than the resulting UI. It needs the executor to thread
  the prior result into the assertion and is deliberately left to a follow-up.
- **Screenshot persistence** — `CaptureEvidence` steps run and are audited, but the
  captured images are not yet written to disk by the runner; seal an evidence
  bundle from the run's audit directory for the durable record.
