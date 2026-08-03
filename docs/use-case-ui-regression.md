# Use case: a UI regression suite that isn't flaky

**The job:** you have an application with a GUI, and the end-to-end tests that
click through it are slow to write and flaky to run. A coordinate moves, a control
re-renders, and a green suite goes red for no real reason.

**Why this helps:** the agent drives the app the way a person does — through the
Windows accessibility tree, targeting controls by their **label**, not their
pixel position. A button that moves is still the same button. And because the same
policy engine and audit chain wrap every run, a test failure comes with evidence
of exactly what the agent saw and did.

You do not need to know the policy engine or the security model to start. This is
the `qa-test-engineer` persona doing what it is for.

## Start it

```powershell
windows-mcp-server.exe stdio --persona qa-test-engineer
```

That persona serves the toolsets a deterministic UI test needs — `screen`,
`interaction`, `apps`, `system`, `filesystem`, `web`, `testing` — and nothing
that would let a test wander off into shell or the registry.

## The loop

The reliable pattern is **observe → act on a label → verify**, repeated:

1. **`Snapshot`** the foreground window — a labelled tree of the interactive
   elements, not a screenshot the model has to interpret.
2. Act on an element **by its label** with **`Invoke`** or **`SetValue`** (the UI
   Automation actions — they do not depend on window focus or coordinates) or
   **`Click`** / **`Type`** where a raw input is what you mean.
3. **`Assert`** the result — a control appeared, text contains a value, a window
   opened. A failed `Assert` is a failed test step, reported as such.
4. **`CaptureEvidence`** at the steps that matter and on failure — a screenshot
   plus the accessibility tree, so a red run is diagnosable without a re-run.

Take a fresh `Snapshot` after the UI changes; do not act on a stale tree.

## Make a run reproducible

- **Record the whole session to video.** Set `transparency.recording_dir` in the
  policy and every run — under any persona — goes to one timestamped file with
  timeline markers. See [Session recording](recording.md).
- **The audit chain** records each tool call with a digest of its arguments, so
  the sequence a test drove is on the record even without the video.
- The `rpa-journey` and `capture-evidence` prompts script the observe-act-verify
  loop and the evidence capture, building their text from the persona's own
  instructions so they cannot drift from it.

## Where it is going

Journeys-as-code — a declarative journey file, versioned in git, run in CI, with a
recorder that writes the file from watching a human do the task once — is on the
[roadmap](../roadmap.md). The persona and the observe-act-verify loop above are the
foundation it builds on, and they work today.

## Related

- [Toolsets and personas](toolsets-and-personas.md) — what each tool does and how
  to trim or extend the persona.
- [User-journey testing (RPA)](../README.md#user-journey-testing-rpa) — the same
  loop from the feature overview.
