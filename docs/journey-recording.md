# Recording a journey

> **Status: mostly implemented.** The selector ladder (§4), verb inference from
> supported patterns (§3), the credential placeholder (§7) and
> **mark-while-recording** (§5.1) all ship. Still on the roadmap: proposing
> assertions from a before/after diff (§5.2), freezing a golden run (§5.3), and
> wait inference (§6) — each marked where it appears.

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

| Property | Used for |
|---|---|
| `AutomationID` | selector rung 1 |
| `Name` | selector rung 2, and the assertion proposed for an id-targeted mark |
| `ControlType` | selector narrowing, and the verb fallback when no patterns are reported |
| `IsPassword` | redaction |
| supported UIA patterns | **verb inference** (§3) and the proposed assertion (§5.1) |
| pattern state — value, checked, selected, expanded | the expected value in a proposed assertion |
| `Rect` | the `point` fallback |
| `ClassName`, `ProcessID`, `Enabled` | read, not yet used |

Two of those lines were the original point of this document, and both were things
the code already had and threw away:

**`AutomationID` was read at every hit-test and discarded.** The enrichment layer
copied only the name and control type into the recorded event, so recordings were
keyed on the rung below the most stable identifier a Windows application offers —
developer-assigned, and unlike the accessible name it survives translation — while
it sat unused in the same struct.

**Supported patterns were not read at all.** The recorder knew *what* was clicked
but not *what it can do*, which is exactly what verb inference needs. It is a
property read on the element already in hand, at the same hit-test, on the same
thread — and it is now read there, in one pass with the pattern state, so the
facts describe a single moment.

---

## 3. Inferring the verb

A click is not a verb. Clicking a checkbox is `toggle`; clicking a list item is
`select`; clicking a chevron is `expand`. Recording every one of them as `click`
throws away what the tree already knows, and produces a journey that drives the
UI through synthetic input when a pattern was available.

Inference reads the patterns the element supports, in order of specificity:

| Supports | Verb |
|---|---|
| Toggle | `toggle` |
| SelectionItem | `select` |
| ExpandCollapse | `expand` / `collapse`, by current state |
| Invoke | `invoke` |
| Value | `click` — focus, for the `type_text` that follows |

The order matters because controls support more than one: a combo box exposes
both ExpandCollapse and Value, and clicking it opens it rather than typing into
it; a list item exposes both SelectionItem and Invoke, and clicking it selects.

Three rules keep this honest:

- **Patterns beat the control type.** A `Button` that exposes Toggle is a toggle
  button, and recording it as `invoke` would produce a step that does the right
  thing by accident and the wrong thing after a redesign. The control type is the
  fallback for a tree that reports no patterns at all, which older frameworks and
  some custom controls do.
- **Fall back to `click`, never guess.** An element supporting no useful pattern
  and carrying no informative control type records as `click`. A wrong verb is
  worse than a general one, because a wrong verb changes what the run does.
- **`expand` versus `collapse` is read from the current state**, not from the
  click — recording `expand` for an already-open node produces a step that closes
  it on the next run. A leaf node reports the pattern but can never expand, so it
  is not treated as expandable.

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

The direct route, and the one that ships: point at what matters and press **F8**.

```
point at the control → F8 → an assertion appears on the step being recorded,
                            with the observed value already filled in
```

The recorder hit-tests under the **pointer**, not under focus — the author is
pointing at the thing they mean, which is rarely the focused control — and
proposes the assertion the element can actually support:

| What the element exposes | Proposed assertion |
|---|---|
| a Value pattern with content | `element.value` `is` *what it currently reads* |
| a Toggle state | `element.checked` `is_true` / `is_false`, as it currently is |
| a SelectionItem state | `element.selected` `is_true` / `is_false` |
| an automation id and a name | `element.name` `is` *the current name* |
| anything else | `element` `exists` |

The expected value is **what is on screen right now**, so the author confirms a
filled-in comparison rather than writing one — a different job, and a much
smaller one. The `element.name` case is worth noting: when the selector is an
automation id, asserting the name is a real check rather than a restatement of
the selector, and a renamed control is exactly the regression an id-targeted
suite would otherwise sail past.

The key is consumed, never recorded, so pressing it never appears as a step. A
mark before any action gets an `observe` to hang from; a mark mid-typing flushes
the typed run first, so characters are never split or dropped.

This is the model Selenium IDE and Playwright's codegen use, and it works for the
same reason: the moment you notice something matters is the moment you are looking
at it.

### 5.2 Propose from what changed — *not yet implemented*

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

### 5.3 Freeze a golden run — *not yet implemented*

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

## 6. Waits, not sleeps — *not yet implemented*

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

Redaction used to emit a placeholder step with empty text — the keystrokes were
correctly never written, but what was left behind was a `type_text` that types
nothing, and a journey that could not run until a human worked out what belonged
there.

The same detection now produces something better. The recorder knows the field
masked its input, so the draft carries an `enter_credential` step with the target
already selected and the credential name left blank:

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
