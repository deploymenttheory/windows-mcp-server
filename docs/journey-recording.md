# Recording a journey

> **Status: design.** A recorder ships today (`journey record`) and captures
> clicks and keystrokes into a version 1 draft with password redaction. What this
> document adds — verb inference, the selector ladder, and the three ways a
> recording acquires assertions — is not implemented. `roadmap.md` tracks the
> phases.

**Nobody is going to hand-write forty steps of JSON.** A vocabulary that only a
determined author can produce is a vocabulary that gets used twice and then
abandoned, however well specified it is. So the closed taxonomy and the recorder
are one design, not a format and a convenience: the recorder is the **primary
author** of a journey and a human is its **editor**.

That framing has a consequence the [taxonomy](journey-taxonomy.md) is written
under. A verb that cannot be inferred from a click plus what the accessibility
tree reports at that instant is a verb only a human will ever write. Such verbs
are allowed — `set_value` is one, and it is the *best* way to fill a field — but
the ratio matters, and §3.3 of the taxonomy is where it is tracked.

```powershell
windows-mcp-server journey record --out journeys/expenses-submit.json --name expenses-submit
# do the task; F8 marks an assertion; F9 stops
```

---

## 1. Why this is not an MCP tool

A journey recorder installs a **low-level global keyboard hook**. That is a
keylogger. It is only not a keylogger because of where it sits: a human at the
console starts it deliberately, it runs for the length of one recording, and the
one thing standing between the capture and a password on disk is a redaction check
that fails **closed** — when UIA cannot report the focused element, the keystroke
is treated as secret and dropped.

Exposing that as a tool on the MCP manifest would hand an agent a keylogger with
an argument for how long to run it. So the recorder is a **CLI verb only**,
reachable in `cmd/windows-mcp-server` and the desktop engine and registered
nowhere in `pkg/windows`. Nothing on the tool surface can start, stop or read a
recording.

This is the same reasoning that keeps the conformance HTTP host behind a build
tag: the capability is legitimate, and the way it is reached is the control.

Two properties follow, and both should be preserved:

- **The draft is written `0o600`**, not `0o644`. A journey is not meant to hold a
  secret, but that rests entirely on redaction being right.
- **The stop key is consumed, not recorded**, so pressing F9 never appears as a
  step in the journey it ended.

---

## 2. What the capture already sees

At every click, the recorder hit-tests the point down the UIA control view and
reads the element under it. What comes back is more than the current draft uses:

| Property | Read today | Used today | Use in v2 |
|---|:---:|:---:|---|
| `Name` | ● | ● | selector rung 2 |
| `ControlType` | ● | ● | verb inference, selector narrowing |
| **`AutomationID`** | ● | — | **selector rung 1** |
| `ClassName` | ● | — | window and app identification |
| `IsPassword` | ● | ● | redaction |
| `Enabled` | ● | — | assertion proposal |
| `Rect` | ● | — | the `point` fallback |
| `ProcessID` | ● | — | which application a step belongs to |
| supported UIA patterns | — | — | **verb inference** |

Two lines in that table are the whole of §3 and §4 below.

**`AutomationID` is read and thrown away.** The enrichment layer copies only the
name and control type into the recorded event. It is the most stable identifier a
Windows application offers — developer-assigned, and unlike the accessible name it
survives translation — and today's recordings are keyed on the rung below it while
it sits unused in the same struct.

**Supported patterns are not read at all.** The recorder knows *what* was clicked
but not *what it can do*, which is exactly the information verb inference needs.
Reading pattern availability is a property read on the element already in hand, at
the same hit-test, on the same thread.

---

## 3. Inferring the verb

A click is not a verb. Clicking a checkbox is `toggle`; clicking a list item is
`select`; clicking a chevron is `expand`. Recording every one of them as `click`
throws away what the tree already knows, and produces a journey that drives the
UI through synthetic input when a pattern was available.

Inference reads the control type and the patterns the element supports:

| Clicked element | Supports | Verb |
|---|---|---|
| CheckBox, RadioButton, ToggleButton | Toggle | `toggle` |
| ListItem, TreeItem, TabItem | SelectionItem | `select` |
| TreeItem, ComboBox, Group with a chevron | ExpandCollapse | `expand` / `collapse`, by current state |
| Button, MenuItem, Hyperlink | Invoke | `invoke` |
| Edit, Document | Value | focus for the `type_text` that follows |
| anything else | — | `click` |

Two rules keep this honest:

- **Fall back to `click`, never guess.** An element supporting no useful pattern
  records as a coordinate-free `click`. A wrong verb is worse than a general one,
  because a wrong verb changes what the run does.
- **`expand` versus `collapse` is read from the current state**, not from the
  click. The recorder knows which way the control was pointing.

Non-click verbs come from the same principle applied to other event sources:
window creation and focus changes give `open_app` / `focus_window` /
`close_window`, a URL in a new browser window gives `navigate`, and wheel events
give `scroll`.

---

## 4. Inferring the selector — the one place ambiguity can be resolved

**The recorder is the only component that can pick a selector correctly**, and
this is the strongest argument for recording over hand-authoring.

At the moment of the click it holds two things nothing else ever holds at once:
the **intended element** — the specific object under the cursor, unambiguously —
and the **whole tree** it sits in. So it can ask a question a human author can
only guess at: *how many other elements would this selector also match?*

The ladder, highest available rung first (taxonomy §4.1):

1. **`automation_id`**, when the application sets one. Survives translation.
2. **`name` + `control_type`**, when the element has an accessible name.
3. **`point`**, when it has neither — recorded, and marked non-durable.

And then the check that hand-authoring cannot make: with the candidate selector
in hand, count the matches in the captured tree.

- **One match** → emit `occurrence: unique`. The default, and now a *verified*
  default rather than a hopeful one.
- **Several matches** → the recorder knows which one the human clicked, so emit
  the explicit index, and say so in the draft's step name so the reviewer sees
  that a choice was made.
- **Several matches and the element has an `automation_id`** → climb the ladder
  instead of indexing. An index is positional and a rung-1 key is not.

This inverts the usual failure. A hand-written `{"name": "Delete"}` is a guess
that there is exactly one Delete on screen, discovered to be wrong on the run
where a second one appeared. A recorded selector was **checked against the actual
tree at the moment it was recorded**.

---

## 5. The assertions problem

This is the real gap, and it is not a small one: **a recording captures actions,
not intent.** A perfect capture of a human submitting an expense claim produces a
journey that verifies nothing at all. It proves the clicks landed. It does not
notice that the total was wrong.

A journey with no assertions is not a test, so the recorder's job is not finished
when it has captured the actions. Three mechanisms, which compose rather than
compete.

### 5.1 Mark an assertion while recording

The direct route: point at what matters and say so.

```
hover the control → F8 → pick a subject → the observed value becomes the expected value
```

Because the recorder is already hit-testing under the cursor, it can offer the
subjects that element actually supports — `element.value` for a field,
`element.checked` for a checkbox, `element.enabled` for a button — and fill
`expected` with **what is on screen right now**. The author confirms rather than
types.

This is the model Selenium IDE and Playwright's codegen use, and it works for the
same reason: the moment you notice something matters is the moment you are looking
at it.

### 5.2 Propose from what changed

The recorder can take a snapshot before and after each action and diff them. What
changed is a strong candidate for what the step was *for*:

| Change | Proposed assertion |
|---|---|
| the foreground window title changed | `window.title` `is` the new title |
| an element appeared | `element` `exists` |
| an element disappeared | `element` `does_not_exist` |
| a field's value changed | `element.value` `is` the new value |
| a control became enabled | `element.enabled` `is_true` |

Proposals are **ranked and offered**, never silently inserted. A step that changed
forty things does not need forty assertions; it needs the one the author cares
about, chosen from a list.

The cost is the snapshot: a bounded tree walk per action, which is real but
affordable — and it must be **debounced**, taken once the UI settles rather than
once per keystroke, or typing a sentence costs a hundred tree walks.

### 5.3 Freeze a golden run

The most powerful of the three, and it costs almost nothing because the evidence
work already did it.

Run the recorded draft once against a known-good build. The
[run record](journey-evidence.md) already carries, for every assertion, what was
expected and **what was observed** — and the same evaluation machinery can read
every subject the taxonomy defines, whether or not an assertion asked for it. So a
run can produce a full observation baseline, and the author promotes the parts
that matter into assertions:

```
windows-mcp-server journey run draft.json --observe-all --out baseline.otlp.json
windows-mcp-server journey freeze draft.json --from baseline.otlp.json
```

The reviewer's question changes from "what should I assert?" — which is hard —
to "which of these observed facts should be true every time?" — which is easy.

The trap to write down now: a golden run **bakes in whatever was on screen**,
including a date, a session id, a generated reference number. Freezing must offer
`matches` with a pattern where a value looks generated, not just `is` with the
literal. A baseline that pins today's date is a suite that fails tomorrow.

---

## 6. Waits, not sleeps

A human waiting for a slow screen produces an idle gap in the event stream. The
naive reading of that gap is a `pause` step, which is exactly the flakiness the
taxonomy tells authors to avoid — it records how long the machine took *once*.

The better reading: an idle gap is a **signal that a wait belongs here**. Pair it
with §5.2's diff — the gap ended when something appeared — and the proposal
becomes a waited assertion on the thing that appeared, with a timeout derived from
the observed delay plus headroom:

```jsonc
// observed: the human waited 4.1s, and the confirmation panel appeared
{ "subject": "element", "target": { "automation_id": "pnlConfirm" },
  "operator": "exists", "wait": { "timeout": 15 } }
```

That is a step that passes in 0.2 seconds on a fast machine and still passes on a
slow one, from a recording that only ever saw 4.1.

---

## 7. Credentials

Redaction currently emits a placeholder step with empty text — the keystrokes are
correctly never written, but what is left behind is a `type_text` that types
nothing, and a journey that cannot run until a human works out what belonged
there.

Under v2 the same detection produces something better. The recorder knows the
field masked its input, so the draft carries an `enter_credential` step with the
target already selected and the credential name left blank:

```jsonc
{ "name": "sign in — supply the credential name before running",
  "verb": "enter_credential",
  "credential": "",
  "target": { "automation_id": "txtPassword" },
  "submit": true }
```

The author fills in one field, and the resulting journey uses the
[credentials](credentials.md) path — where the agent can *use* a secret and never
*read* one — rather than having a password typed back into a document.

The redaction guarantee itself does not change and must not: it fails closed, it
ignores input injected by a concurrent agent session, and it is pinned by a test
that asserts a recorded journey never contains the secret.

---

## 8. The draft is a proposal

Whatever the inference achieves, the output of `record` is a **draft**, and the
review step is not optional. The recorder observes what was done; only the person
who did it knows why. Concretely, a reviewer is deciding:

- **Which actions were incidental.** A stray click, a scroll to find something, a
  correction. They were real, and they do not belong in the test.
- **Which assertions matter.** Of everything that changed, the two or three facts
  that constitute the journey having worked.
- **Where `type_text` should be `set_value`.** Typing is what happened; the
  pattern is what should run.
- **Where a value is generated.** See §5.3 — this is the one a reviewer is
  uniquely able to spot.

A recorded journey that has been run once and never read is a journey that asserts
its own clicks landed. That is worth saying in the output of `record` itself, not
only here.

---

## 9. Deliberately not covered

- **Re-recording one step of an existing journey.** Genuinely useful and a
  significantly larger piece of work: it needs the recorder to align a new capture
  against an existing document, which is a diff over intent rather than over text.
  Re-record the journey.
- **A GUI editor.** The draft is JSON in a text editor, reviewed like code, in
  git. That is the point of journeys-as-code; an editor that hides the document
  hides the diff.
- **Recording an agent session.** An agent's tool calls are already on the audit
  chain and can be replayed from there. Watching the agent through the input hooks
  would capture synthetic input the redaction path deliberately ignores.
- **Cross-machine portability of `point` targets.** A coordinate is valid for one
  resolution and one layout. The ladder in §4 exists so that almost nothing
  depends on one.
