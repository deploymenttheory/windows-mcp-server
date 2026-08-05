# Journey evidence

> **Status: implemented, with two gaps.** The span model, the attribute registry,
> the OTLP/JSON artifact, screenshot persistence, the bundle members and the
> post-run evidence check all ship. Not yet wired: **live export** of journey
> spans to a collector (§7), and the three **resolved-selector** attributes
> (§2) — both noted where they appear.

What a [journey](journeys.md) run records, in what shape, and where it ends up.

The requirement is narrow and hard: after a run, someone who was not watching must
be able to establish **what was asserted, what was actually observed, and whether
that matched** — for every step, months later, from an archive. A rendered text log
does not carry that. It says an assertion failed; it does not say what was on
screen instead.

**A run is a trace.** The record is OpenTelemetry, in the OTLP/JSON encoding, and
there is one model with two sinks: exported live to a collector over the OTLP/HTTP
path the server already has, and written to disk as the artifact that gets sealed
into an [evidence bundle](evidence-bundles.md). Fleet monitoring and forensic
evidence stop being two formats that have to be kept in agreement.

---

## 1. The span model

| Span | Parent | Name | Kind |
|---|---|---|---|
| the run | root | `journey <name>` | Internal |
| a step | run | `<verb> <target>` | Internal |
| an assertion | step | `assert <subject> <operator>` | Internal |
| a capture | step | `capture <label>` | Internal |

```
journey expenses-submit                         3.94s   Ok
├─ open_app "Contoso Expenses"                  1.71s   Ok
│  ├─ assert window.title contains              0.42s   Ok      polls 2
│  └─ capture "app opened"                      0.19s   Ok
├─ observe                                      0.11s   Ok
├─ set_value "Amount"                           0.08s   Ok
├─ observe                                      0.10s   Ok
├─ click "Submit"                               0.12s   Ok
│  └─ assert element exists                     1.02s   Ok      polls 3
├─ observe                                      0.10s   Ok
└─ read "Reference"                             0.09s   Ok
   ├─ assert result.text matches                0.01s   Error   observed "EXP-4471"
   └─ capture "claim submitted"                 —       skipped
```

The compiler-inserted `observe` steps (taxonomy §4.2 rule 3) appear as spans of
their own, so the trace shows when perception happened and not merely when action
did — which is what lets you tell a stale-snapshot failure from a genuine one.

**Status** is `Ok` on pass and `Error` on fail, with the description carrying the
comparison: `expected "EXP-[0-9]{6}", observed "EXP-4471"`. The run span's status
is the run's verdict.

A span is emitted for **every** assertion, including the ones that passed. A
record that only carries failures cannot answer "was this ever checked?", which is
the question an auditor actually asks.

The same machinery has a second use worth designing for from the start. It can
read every subject the taxonomy defines, not only the ones an assertion asked
about — so a run can emit a full **observation baseline**, and a recorded draft
with no assertions can be run once and have its observations promoted into
assertions. That is the "freeze a golden run" workflow in
[recording a journey](journey-recording.md#53-freeze-a-golden-run), and it is the
main reason authoring a journey does not have to mean writing one.

---

## 2. The attribute registry

Names follow OpenTelemetry semantic-convention rules: lowercase, dot-separated
namespaces, no units in names, and no collision with registered semconv keys. The
namespace is `journey.*`. The only existing precedent in this server is `mcp.tool`,
which stays as it is.

### On the run span

| Attribute | Type | Value |
|---|---|---|
| `journey.name` | string | the document's `name` |
| `journey.version` | int | the schema version (`2`) |
| `journey.document.sha256` | string | SHA-256 of the canonical document |
| `journey.plan.id` | string | the compiled plan's id |
| `journey.session.id` | string | the run's session stamp |
| `journey.steps.total` | int | steps in the compiled plan |
| `journey.steps.completed` / `.failed` / `.skipped` | int | outcome counts |
| `journey.passed` | bool | the verdict |

### On a step span

| Attribute | Type | Value |
|---|---|---|
| `journey.step.index` | int | position in the compiled plan |
| `journey.step.name` | string | the author's step name, if any |
| `journey.step.verb` | string | the verb |
| `journey.step.tool` | string | the tool the verb lowered to |
| `journey.step.outcome` | string | `ok` / `failed` / `refused` / `not_approved` |
| `journey.step.verdict` | string | the policy severity the step was evaluated at |
| `journey.step.synthetic` | bool | true for a compiler-inserted `observe` |
| `journey.selector.automation_id` | string | the selector's `automation_id` |
| `journey.selector.name` | string | its `name` |
| `journey.selector.control_type` | string | its `control_type` |
| `journey.selector.name_match` | string | `exact` / `contains` / `matches` |
| `journey.selector.occurrence` | string | `unique` / `first` / an index |
| `journey.selector.scope` | string | `foreground` / `any_window` |
| `journey.selector.durable` | bool | false for a `point` target |

`journey.selector.durable` makes coordinate fragility a queryable property of a
suite — "nine of our sixty steps target coordinates" — rather than a suspicion
raised after the third mystery failure.

**Not yet emitted:** `journey.selector.candidates`, `.resolved.name` and
`.resolved.control_type` — how many elements the selector matched and which one
was acted on. Together they answer the question a UI suite most often cannot:
*which control did it actually press?* The resolver computes the count already
(it is what makes ambiguity an error rather than a silent pick), but nothing
reports it back out of the tool call, so wiring it needs the same kind of
side-channel register the observed value uses. Until then an ambiguous selector
is visible only as the failure it causes, whose message does name the candidates.

### On an assertion span

| Attribute | Type | Value |
|---|---|---|
| `journey.assertion.subject` | string | e.g. `element.value` |
| `journey.assertion.operator` | string | e.g. `is` |
| `journey.assertion.expected` | string | the expected value, rendered |
| **`journey.assertion.observed`** | string | **what was actually read** |
| `journey.assertion.passed` | bool | |
| `journey.assertion.message` | string | the author's description |
| `journey.assertion.polls` | int | evaluations performed (1 when not waited) |
| `journey.assertion.timeout` | double | the wait budget in seconds, if any |

`journey.assertion.observed` is the reason this document exists. A failure that
reports only the condition name tells you a test broke; one that reports the
observed value usually tells you *why*, without a second run on a machine that has
since moved on.

Observed values are **clipped** to a documented length. They come from the screen,
so they are the same class of data as a snapshot — and unlike tool arguments,
which the audit chain deliberately reduces to a digest, an assertion's observed
value has to be legible or the record is pointless. That is a considered
difference, not an inconsistency: the audit chain proves *what happened*, the run
record proves *what was seen*.

### On a capture span

| Attribute | Type | Value |
|---|---|---|
| `journey.evidence.label` | string | the caption from the document |
| `journey.evidence.path` | string | bundle-relative path of the image |
| `journey.evidence.sha256` | string | SHA-256 of the image bytes |
| `journey.evidence.width` / `.height` | int | pixels |

### Resource attributes

`service.name` and `service.version` are set today. Two are added, and both are
about correlation:

| Attribute | Why |
|---|---|
| `session.id` | the session stamp that names `session-<stamp>.audit.jsonl` and the recording. Without it a trace cannot be tied to the audit chain it belongs to — the correlator exists but has never reached OTLP. |
| `host.name` | which machine ran it, for a fleet where that is not obvious from the collector. |

---

## 3. The artifact

```
journeys/expenses-submit-20260805-141233.otlp.json
```

OTLP/JSON: the standard `ResourceSpans` encoding, so a collector, `otel-cli`, a
Jaeger import or any OTLP-aware tool reads it with no bespoke parser. Trace and
span ids are hex strings, timestamps are Unix nanoseconds as strings, per the
proto3 JSON mapping.

```jsonc
{
  "resourceSpans": [{
    "resource": { "attributes": [
      { "key": "service.name", "value": { "stringValue": "windows-mcp-server" } },
      { "key": "session.id",   "value": { "stringValue": "20260805-141233" } }
    ]},
    "scopeSpans": [{
      "scope": { "name": "windows-mcp-server/journeys" },
      "spans": [{
        "traceId": "4bf92f3577b34da6a3ce929d0e0e4736",
        "spanId":  "00f067aa0ba902b7",
        "parentSpanId": "a3ce929d0e0e4736",
        "name": "assert result.text matches",
        "startTimeUnixNano": "1786055553120000000",
        "endTimeUnixNano":   "1786055553131000000",
        "attributes": [
          { "key": "journey.assertion.subject",  "value": { "stringValue": "result.text" } },
          { "key": "journey.assertion.operator", "value": { "stringValue": "matches" } },
          { "key": "journey.assertion.expected", "value": { "stringValue": "EXP-[0-9]{6}" } },
          { "key": "journey.assertion.observed", "value": { "stringValue": "EXP-4471" } },
          { "key": "journey.assertion.passed",   "value": { "boolValue": false } },
          { "key": "journey.assertion.polls",    "value": { "intValue": "1" } }
        ],
        "status": { "code": 2, "message": "expected \"EXP-[0-9]{6}\", observed \"EXP-4471\"" }
      }]
    }]
  }]
}
```

### Four things to get right, because each will otherwise bite

**1 — Evidence must never be sampled.** The policy document's
`telemetry.sample_ratio` governs what is *exported*; it must not govern what is
*recorded*. A run record with a statistical subset of its own steps is not
evidence. `internal/runrecord` is therefore wholly independent of the exporter
and its sampler: it builds the spans itself and every one of them is kept.

**2 — The OTel Go SDK has no file exporter.** So the spans are built directly as
OTLP protocol buffers (`go.opentelemetry.io/proto/otlp`, promoted from an
indirect dependency) and encoded with `protojson`. Routing them through the SDK
instead would mean a `TracerProvider`, which puts evidence behind a sampler —
see rule 1. There was no existing serializer in this repo to reuse: everything
written to disk before this was the server's own format.

**3 — `protojson` output is deliberately unstable.** It injects randomised
whitespace specifically to discourage byte comparison of its output. The artifact
is SHA-256'd into a bundle manifest and compared on verification, so it **must**
be canonicalised before writing — decode the `protojson` output into a generic
value and re-encode with `encoding/json`, which sorts object keys. Skipping this
produces a file that hashes differently every time it is written and a
verification step that fails for no reason anybody can see.

**4 — Trace and span ids are random, and should stay random.** Two runs of the
same document produce different ids and therefore different files. That is
correct: the run differs. The *stable* identity is `journey.document.sha256` (what
was run) and `journey.plan.id` (what was approved). Nobody should later make ids
deterministic to get reproducible files; reproducibility belongs to the document,
not to the run.

---

## 4. Captured images

A `capture` verb writes a real file:

```
evidence/03-claim-submitted.png
```

`NN` is the capture's ordinal in the run, so images sort in execution order, and
the label is slugified. The path and SHA-256 go on the capture span, so the record
names the image and the manifest proves it has not been altered since.

This closes a documented gap: captures previously ran, were audited, and returned
an image to the model — and wrote nothing to disk, so the durable record of a run
contained no pictures of it.

Images are written only when the run has an evidence directory. A `journey run`
with nowhere to write them captures the snapshot text and records the span without
a path, rather than failing — a missing output directory is a configuration
choice, not a test failure.

---

## 5. In the evidence bundle

A sealed bundle gains two member groups:

```
manifest.json                  ← already present; now covers the members below
manifest.sig
audit/session-20260805-141233.audit.jsonl
verdicts.json
journeys/expenses-submit-20260805-141233.otlp.json
evidence/01-app-opened.png
evidence/03-claim-submitted.png
recording/session-20260805-141233.mp4
```

Both are hashed into `manifest.json` by the existing sealer, so a journey's
evidence is covered by the same Ed25519 signature and the same
`audit_head` cross-check as everything else. Nothing new is needed for
verification — the members are files, and the bundle already proves files.

`journey.` joins the verdict prefixes the bundle extracts into `verdicts.json`, so
a run's `journey.started` / `journey.finished` reach the summary a reviewer opens
first. They do not today: a bundle sealed from a journey run contains the
`plan.*` entries for each step but no record of the journey's own verdict.

### Correlation

Four artifacts, one identity. The session stamp names the audit file, the
recording and the run record; `session.id` carries it into the trace; the audit
chain's `journey.finished` and the run span carry the same `plan_id`. From any one
of them you can reach the other three, which is what makes the bundle an
investigation rather than a folder.

---

## 6. Expected evidence, checked after the fact

`expected_evidence` currently means "some step in this document claims it will
capture this" — a statement about the document, verified against the document. It
becomes a statement about the run: **a run that did not capture every expected
label fails, even if every assertion passed.**

The difference matters when a run fail-stops. Under the old check, a journey that
died at step 2 still "satisfied" its evidence expectations, because they were
satisfied at validate time by steps that never ran.

---

## 7. Live export — not yet wired

A journey run executes through the planner and never touches the MCP middleware
chain, so it emits none of the per-request `tools/call` spans the
[monitoring](monitoring.md) path produces. The run record is built by the journey
runner's own recorder, and **written to disk only**: nothing is currently sent to
a collector.

Adding it is a small piece of work — the spans already exist in the right shape —
but it is deliberately not free, and the reason is worth settling before it is
done. Assertion *observed* values are screen content. Exporting them sends what
was on a user's screen off the machine, which is the one thing the
accessibility-tree-only design otherwise guarantees against. That is why the file
artifact and any future export must stay **separately configurable**: a fleet
should be able to seal full evidence locally and export nothing, or export the
outcome without the observations.

Tool arguments are never exported either way, matching the audit chain.

---

## 8. Deliberately not covered

- **A bespoke JSON result schema.** An OTel-shaped record is readable by tooling
  that already exists; a schema of our own would need a viewer of our own.
- **Metrics per journey run.** A pass/fail counter tagged by journey name is a
  cardinality problem in a fleet, and the trace already carries the outcome.
- **Video correlation by timestamp.** The recording and the run share a session
  stamp, which is enough to find the video. Frame-accurate seeking to a failed
  step is real, useful, and a larger piece of work.
- **Chaining the run record into the audit hash chain.** The chain records that a
  journey ran and how it ended; the run record is a bundle member covered by the
  manifest signature. Two mechanisms, each doing what it is good at.
