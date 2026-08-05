# Journey taxonomy

> **Status: implemented and normative.** This specifies journey schema **version
> 2**, which is what the build accepts. The vocabularies below are expressed as
> data in `internal/journeys/vocabulary.go` and pinned against this document by
> the package's tests, so a table here and a table there cannot drift apart
> silently.

**This document is normative.** It defines the closed vocabularies a journey
document is written in — verbs, selectors, subjects, operators — and the rules that
make a journey deterministic. [Journeys as code](journeys.md) is the authoring
guide and defers to this document for anything binding; [journey
evidence](journey-evidence.md) defines what a run records.

Everything here is a **closed set**. There is no extension point, no expression
language and no escape hatch, and that is the design rather than an unfinished
edge. A vocabulary you can enumerate is one a validator can check offline, a
reviewer can read in a diff, and a change manifest can be **derived** from rather
than told about. An open one is none of those things, however expressive.

---

## 1. The framing rule

> A journey is a **total order of steps with no control flow.** No conditionals,
> no loops, no variables, no arithmetic, no expressions. Every run of the same
> document attempts the same operations against the same targets in the same
> order — or it fails and says where.

Everything else in this document exists to serve that sentence. It is also what
separates a journey from a script: anything that needs to branch is two journeys,
and anything that needs a shell is a [plan](plan-and-apply.md).

The three consequences worth stating outright, because each is a property
somebody will later be tempted to trade away:

- **A journey is diffable.** Two versions of a document differ in the vocabulary a
  reviewer already knows, not in code paths they have to simulate mentally.
- **A journey is hashable.** The document has one canonical form, so an approval
  and an audit entry can bind to exact content.
- **A journey's reach is derivable.** Because the verb set is closed (§3), the
  server can compute what a journey touches from the document alone. It never has
  to trust a declaration, and there is nothing for a document to understate.

And one constraint that runs the other way, which the rest of this document is
written under: **the vocabulary has to be one a machine can generate.** Nobody is
going to hand-write forty steps of JSON, so the [recorder](journey-recording.md)
is the primary author and a human is an editor. A verb that cannot be inferred
from a click plus what the accessibility tree reports at that instant is a verb
only a human will ever write — which is allowed, but should be rare enough to
notice. §3.3 records where the vocabulary is deliberately wider than the recorder
can reach.

---

## 2. The document

```jsonc
{
  "version": 2,
  "name": "expenses-submit",
  "description": "Submit an expense claim and confirm the reference number.",
  "steps": [ /* §2.1 */ ],
  "expected_evidence": [ "claim submitted" ]
}
```

`version` is `2`. Version 1 is not accepted and there is no conversion: it named
MCP tools and carried untyped arguments, which is precisely what this taxonomy
replaces. Unknown fields are rejected at parse, so a typo in a key fails at
`journey validate` rather than being silently dropped.

### 2.1 A step

```jsonc
{
  "name": "enter the amount",          // optional; labels the step in reports
  "verb": "set_value",                 // §3 — required, from the closed set
  "target": { "name": "Amount", "control_type": "Edit" },   // §4
  "value": "126.40",                   // verb parameter, typed per verb
  "assertions": [ /* §5 */ ],          // checked after the action
  "evidence": [ "amount entered" ]     // §6 — captions to capture after the action
}
```

A step is one action, the conditions that must hold after it, and the evidence to
capture at that point. The action's parameters are **typed per verb** — there is
no `args` bag. `set_value` takes a `value`; `press_keys` takes `keys`; passing
`value` to `press_keys` is a validation error, offline, before anything runs.

---

## 3. Verbs

Verbs are named for **user intent**, not tool mechanics: an author writes what a
person would do, and the compiler decides which tool call expresses it. That
indirection is what lets the tool surface change — a better UIA path, a renamed
argument — without invalidating a checked-in suite, and it is why `enter_credential`
takes a `target` like every other verb even though the underlying `Credentials`
tool spells that argument `name_target` because its own `name` means the
credential.

Each verb has a **fixed lowering**: a declared sequence of tool calls, the same
every time. Most are a single call. The lowering is part of this specification,
not an implementation detail, because it is what the audit chain and the change
manifest will show.

### 3.1 The set

| Group | Verb | Parameters | Lowers to |
|---|---|---|---|
| **Lifecycle** | `open_app` | `app` | `App{mode:launch, name:app}` |
| | `focus_window` | `window` | `App{mode:switch, name:window}` |
| | `resize_window` | `window`, `position?`, `size?` | `App{mode:resize, …}` |
| | `close_window` | `window` | `App{mode:switch}` → `Shortcut{alt+F4}` |
| **Navigation** | `navigate` | `url` | `App{mode:launch, name:url}` |
| | `scroll` | `target?`, `direction`, `amount?` | `Scroll` |
| **Manipulation** | `click` | `target` | `Click{clicks:1}` |
| | `double_click` | `target` | `Click{clicks:2}` |
| | `right_click` | `target` | `Click{button:right}` |
| | `hover` | `target` | `Click{clicks:0}` |
| **Control ops** | `invoke` | `target` | `Invoke{action:invoke}` |
| | `toggle` | `target` | `Invoke{action:toggle}` |
| | `select` | `target` | `Invoke{action:select}` |
| | `expand` | `target` | `Invoke{action:expand}` |
| | `collapse` | `target` | `Invoke{action:collapse}` |
| **Text entry** | `set_value` | `target`, `value` | `Invoke{action:set_value}` |
| | `type_text` | `target?`, `text`, `submit?` | `Type{text, press_enter}` |
| | `clear` | `target` | `Type{clear:true, text:""}` |
| | `press_keys` | `keys` | `Shortcut{shortcut:keys}` |
| | `enter_credential` | `credential`, `target?`, `submit?` | `Credentials{mode:inject}` |
| **Perception** | `observe` | `scope?` | `Snapshot{all_windows}` |
| | `read` | `target` | `GetText` |
| | `capture` | `label` | `CaptureEvidence{label}` |
| **Synchronisation** | `pause` | `seconds` | `Wait{duration}` |

`?` marks an optional parameter. `direction` is `up`/`down`/`left`/`right`;
`scope` is defined in §4; `submit` presses Enter after the entry, which is one
keystroke and one intention rather than two steps that can drift apart.

`enter_credential`'s target is optional because injecting into the already-focused
field is legitimate, and a recorded draft where the human tabbed into the password
box has no click to attach a selector to. The credential name is **not** optional,
and a recorded draft leaves it blank on purpose: the draft does not validate until
a human names the stored credential, which is better than a journey that runs and
silently types nothing into a sign-in form.

### 3.2 Four rules about the set

**`press_keys` is execution, not interaction.** `win+r` opens the Run dialog;
`ctrl+shift+esc` opens Task Manager. A key chord is arbitrary reach into the
shell, which is why the underlying `Shortcut` tool carries `DestructiveHint` and
why this verb derives `execute` in §7. The verb table must never launder that into
something that reads like a click.

**`pause` is the escape hatch of last resort.** A fixed sleep is the single most
common way a UI suite becomes flaky: it passes on the machine it was written on
and fails on a slower one, and it wastes the difference on a faster one.
Synchronisation belongs on an assertion's `wait` modifier (§5.5), which polls for
a *stated* condition and records how long it actually took — turning "wait a bit"
into a measurement. `pause` exists for the genuinely untestable case (an animation
with no completion signal) and should be rare enough to notice in review.

**There is no `raw` verb.** A journey covers user journeys. Anything that needs
`PowerShell`, `Registry`, `FileSystem` or `Process` is a
[plan](plan-and-apply.md), which stays tool-shaped and general on purpose. Keeping
the escape hatch out is what makes "every journey step is an attested verb" true
without a footnote — and a footnote is exactly what an attestation cannot afford.

**A verb never spans applications implicitly.** `close_window` focuses the window
before sending `alt+F4`, because sending it to whatever happens to be foreground
is how a journey closes the wrong thing. Where a lowering needs more than one call
to be unambiguous, it takes more than one call, and this document says so.

### 3.3 What the recorder can reach

Every verb is classified by whether a recording can produce it. The point of the
table is not the classification but the ratio: if the human-only column grows,
the vocabulary has drifted away from the tool that is supposed to write it.

| | Verbs |
|---|---|
| **Inferred from a click** | `click`, `double_click`, `right_click`, `invoke`, `toggle`, `select`, `expand`, `collapse` |
| **Inferred from keyboard input** | `type_text`, `press_keys`, `clear` |
| **Inferred from window events** | `open_app`, `focus_window`, `close_window`, `navigate` |
| **Inferred from a gesture** | `scroll` |
| **Proposed, confirmed by a human** | `enter_credential` (from a redacted run), `pause` (from an idle gap — usually rewritten as a wait) |
| **Human-only** | `set_value`, `read`, `capture`, `observe`, `resize_window` |

`set_value` is the interesting one. It is the *preferred* way to fill a field —
UIA patterns do not depend on focus and cannot be stolen by a notification — but a
recording of a human typing produces `type_text`, because typing is what happened.
That is a legitimate upgrade for a reviewer to make, and the recorder should
suggest it where the field supports the Value pattern rather than silently
rewriting history.

`read`, `capture` and `observe` are not actions a person performs, so there is
nothing to observe. They come from the assertion and evidence workflow in
[journey recording](journey-recording.md), not from watching the desktop.

---

## 4. Selectors

A selector names the UI element or window a verb acts on. It is where almost all
of a journey's determinism lives, because it is where a document's intent meets a
screen that is never quite the same twice.

```jsonc
"target": {
  "automation_id": "btnSubmit", // the developer-assigned id, when the app sets one
  "name": "Submit",             // the accessible name
  "control_type": "Button",     // optional; narrows the match
  "name_match": "exact",        // exact (default) | contains | matches
  "occurrence": "unique",       // unique (default) | first | <integer>
  "point": [1204, 663],         // the last resort
  "scope": "foreground"         // foreground (default) | any_window
}
```

Exactly one of `automation_id`, `name` or `point` identifies the element;
`control_type` may narrow any of them. `name_match` qualifies `name` and belongs
only with it — an `automation_id` is an identifier, so it is matched exactly and
there is nothing to relax.

### 4.1 The stability ladder

The three identifying keys are not equivalent, and a selector should use the
highest rung the application makes available:

| Rung | Key | Survives |
|---|---|---|
| 1 | `automation_id` | relayout, restyling, **translation**, and renamed labels |
| 2 | `name` + `control_type` | relayout and restyling |
| 3 | `point` | nothing; it is a coordinate |

`automation_id` is developer-assigned and is the closest thing a Windows
application has to a test id. It is stable across localisation, which nothing else
here is — a suite keyed on `name` is a suite that breaks the day it is run against
a French build.

The [recorder](journey-recording.md) picks the highest available rung
automatically. This matters more than it looks: the capture path already reads
`AutomationID` at every click and currently discards it, so today's recordings are
keyed on rung 2 when rung 1 was sitting there.

### 4.2 The rules

**1 — `name_match` defaults to `exact`.** Matching is against the **whole** name.
Substring matching remains available as `contains`, and `matches` takes an RE2
pattern under the rules in §5.4, but neither happens unless an author asked for
it.

*Why:* the resolver this replaced tried an exact pass and then silently fell back
to substring, so `"Save"` resolved to `"Save As…"` on any screen where no exact
match existed — and the journey passed, having clicked the wrong control. A
fallback that changes which element you get, based on what else happens to be on
screen, cannot be part of a deterministic vocabulary.

Exact is **case-insensitive**, which is the one relaxation kept. Case folding
cannot widen a selector onto a differently-named control; it can only merge two
that differ by case alone, and rule 2 then reports that as ambiguity rather than
resolving it arbitrarily. Requiring exact case would break a selector on a
capitalisation change no user can see, for no determinism gained.

**2 — `occurrence` defaults to `unique`, and ambiguity is a failure.** If a
selector matches more than one element, the step fails and the failure names the
candidates. Choosing among matches is legal (`first`, or a 0-based integer) but
must be written down.

*Why:* silently taking index 0 makes the outcome depend on tree ordering, which
changes when a developer adds a control nobody thought was related. A journey that
picks among matches should say it is doing so, and a journey that did not expect
matches at all should find out on the run where the second one appeared — not
three releases later.

**3 — Perception is per step, never ambient.** Every selector-bearing verb
resolves against a snapshot taken as part of that step. The compiler emits an
`observe` immediately before such a verb unless the preceding step is already
one. An assertion perceives for itself: a targeted assertion reads the screen at
the moment it is evaluated, and a polled one re-reads it on every poll — which is
what makes polling mean anything.

*Why:* element resolution reads the most recent snapshot, whatever that is. A
document that never observes resolves against state left behind by something else,
and the same document can behave differently depending on what ran before it.
Making perception an explicit step also puts the moment of observation on the
audit chain and in the change manifest, where it can be reviewed.

**4 — `point` is legal, and marked.** The recorder falls back to coordinates for
controls with no accessible name, so coordinate targeting has to stay possible. A
point-targeted step is flagged as non-durable in the change manifest and carries
`journey.selector.durable = false` in the run record.

*Why:* coordinate fragility should be a **queryable fact about a suite**, not a
suspicion someone raises after the third mystery failure. "Nine of our sixty steps
target coordinates" is a sentence you can act on.

**5 — `scope` decides how wide the search is.** `foreground` (the default)
resolves within the active window; `any_window` searches every visible window and
lowers to `Snapshot{all_windows: true}`. Widening the search widens the chance of
ambiguity, which rule 2 then turns into a failure rather than a coin toss.

### 4.3 What a selector may not do

No CSS/XPath-style paths, no ancestor or sibling axes, no "the element after the
one labelled X". Those express *structure*, and accessibility-tree structure is
the least stable thing about a Windows application — it changes with a framework
upgrade that changed nothing a user can see. Name, control type and an explicit
occurrence are what survive.

---

## 5. Assertions

An assertion is one condition checked after a step. Failing one fails the step,
which stops the run — a journey is a test, so it stops at the first thing that is
not true.

```jsonc
{
  "subject":  "element.value",
  "target":   { "name": "Total", "control_type": "Text" },
  "operator": "is",
  "expected": "£126.40",
  "message":  "the total reflects the amount entered",
  "wait":     { "timeout": 15 }
}
```

The shape is **subject × operator × expected**, not a list of named conditions.
The kinds it replaces (`text_present`, `element_present`, `window_active`, and a
`wait_`-prefixed twin for each) were a fixed grid of seven cells that could only
grow by multiplication, over an overloaded `target` field that meant tree text,
element name or window title depending on which cell you were in.

### 5.1 Subjects

Every subject has a **value type**. The type is what decides which operators are
legal (§5.3).

| Subject | Type | Reads | Needs `target` |
|---|---|---|---|
| `screen.text` | text | all text in the UI tree | no |
| `window.title` | text | the foreground window's title | no |
| `window` | existence | a window matching the selector | yes |
| `element` | existence | the selector resolves to an element | yes |
| `element.name` | text | its accessible name | yes |
| `element.value` | text | its value (UIA Value pattern) | yes |
| `element.control_type` | text | its control type | yes |
| `element.enabled` | boolean | whether it accepts input | yes |
| `element.checked` | boolean | its toggle state | yes |
| `element.selected` | boolean | its selection state | yes |
| `element.focused` | boolean | whether it holds focus | yes |
| `element.count` | number | how many elements the selector matches | yes |
| `result.text` | text | what the preceding `read` returned | no |

Two notes:

- **`element.count` is the one subject that does not fail on ambiguity.** Counting
  matches is the question, so §4.2 rule 2 does not apply to it. It is how you
  assert "there are exactly three rows" or "the error list is empty".
- **`result.text` is the register.** A `read` verb puts what it read into a
  run-scoped register; an assertion with this subject reads it. This is what
  closes the long-standing `result_contains` gap — asserting on what a step
  *returned* rather than on what the screen looks like afterwards.

  The mechanism matters for governance: the register is supplied to the assertion
  by the executor as **environment**, and is never spliced into the assertion's
  arguments. Plan steps run verbatim from the stored, approved document, and their
  argument digest is what the audit chain records — rewriting arguments at
  execution time would break both. So `result.text` is a reference the assertion
  resolves at run time, not a value the executor substitutes into it.

### 5.2 Operators

| Operator | `expected` | Meaning |
|---|---|---|
| `is` | scalar | exactly equal |
| `is_not` | scalar | not exactly equal |
| `contains` | string | contains the substring |
| `does_not_contain` | string | does not contain it |
| `starts_with` | string | has the prefix |
| `ends_with` | string | has the suffix |
| `matches` | string | full match against an RE2 pattern (§5.4) |
| `does_not_match` | string | no full match |
| `is_empty` | — | the empty string |
| `is_not_empty` | — | not the empty string |
| `is_one_of` | array | equal to some member |
| `is_not_one_of` | array | equal to no member |
| `is_true` | — | true |
| `is_false` | — | false |
| `exists` | — | present |
| `does_not_exist` | — | absent |
| `greater_than` | number | strictly greater |
| `greater_or_equal` | number | greater or equal |
| `less_than` | number | strictly less |
| `less_or_equal` | number | less or equal |

An operator marked `—` takes no `expected`, and supplying one is a validation
error. Silently ignoring a field the author wrote is how a document comes to mean
something other than it says.

### 5.3 The matrix

**This table is the taxonomy.** It is validated offline and pinned by a
table-driven test, so an unlisted combination fails `journey validate` rather
than a run.

| Operator | text | number | boolean | existence |
|---|:---:|:---:|:---:|:---:|
| `is` / `is_not` | ● | ● | ● | |
| `contains` / `does_not_contain` | ● | | | |
| `starts_with` / `ends_with` | ● | | | |
| `matches` / `does_not_match` | ● | | | |
| `is_empty` / `is_not_empty` | ● | | | |
| `is_one_of` / `is_not_one_of` | ● | ● | | |
| `is_true` / `is_false` | | | ● | |
| `exists` / `does_not_exist` | | | | ● |
| `greater_than` / `greater_or_equal` | | ● | | |
| `less_than` / `less_or_equal` | | ● | | |

`is` and `is_not` are deliberately available for booleans as well as `is_true` /
`is_false`, because `{"operator": "is", "expected": false}` reads naturally in a
document generated by tooling while `is_false` reads better in one written by
hand. They are the same check.

### 5.4 Text comparison

Comparison is **exact, case-sensitive, and Unicode NFC-normalised**, with three
modifiers that default off:

| Modifier | Effect |
|---|---|
| `ignore_case` | Unicode simple case folding on both sides |
| `trim` | strip leading and trailing whitespace from the observed value |
| `collapse_whitespace` | collapse internal whitespace runs to one space |

*Why explicit:* the behaviour being replaced folded case for window titles and not
for anything else, and said so nowhere. A comparison whose rules depend on which
condition you picked is not a comparison an author can reason about.

`matches` and `does_not_match` take an **RE2** pattern and require a **full
match** — the pattern is anchored at both ends. Use `contains` for a substring, or
write `.*` explicitly. Full-match is the deterministic default: an unanchored
pattern that happens to match a fragment is the regex equivalent of the substring
fallback rule 1 removes.

Patterns are compiled at `journey validate` time, so an invalid one fails offline
rather than mid-run, and are capped at 512 characters. RE2 does not backtrack, so
a pathological pattern cannot hang a run — the cap is about reviewability, not
safety.

### 5.5 `wait` is a modifier

```jsonc
"wait": { "timeout": 15, "interval": 0.4 }
```

Any assertion may carry `wait`. With it, the condition is polled until it holds or
the timeout expires; without it, it is evaluated once. `timeout` is in seconds
(default 10, maximum 120); `interval` is the poll period in seconds (default 0.4).

One orthogonal modifier replaces an entire parallel family of `wait_`-prefixed
conditions, and with it the two-vocabulary split where the same three checks were
called `text_present`/`element_present`/`window_active` in one place and
`text_exists`/`element_exists`/`active_window` in another, reconciled by a
hand-maintained mapping.

The run record reports polls and elapsed time for **every** assertion, waited or
not, so "passed immediately" and "passed after 14.6 of its 15 seconds" are
different facts. That is what makes a suite's drift toward flakiness measurable
before it becomes failure.

`message` is carried through to the result of every assertion, polled or not. In
the shape being replaced it was silently dropped for all three polled kinds,
because the underlying tool had nowhere to put it — so exactly the assertions most
likely to fail were the ones that failed without the author's explanation.

---

## 6. Evidence declarations

```jsonc
"evidence": [ "claim submitted" ]           // on a step
"expected_evidence": [ "claim submitted" ]  // on the journey
```

A step's `evidence` labels are captured after the action and its assertions.
`expected_evidence` states what a passing run must produce.

Labels are free-form text, matched by exact equality. Two checks apply, and the
second is the one that means anything:

- **At validate time**, every `expected_evidence` label must be produced by some
  step, or the expectation could never be met by any run.
- **After a run**, every `expected_evidence` label must actually have been
  captured, or the run **fails** — even if every assertion passed.

See [journey evidence](journey-evidence.md) for what a capture writes and where it
lands.

---

## 7. Derivation: what a journey is attested to touch

Every verb maps to a fixed `(kind, verb)` pair in the [plan](plan-and-apply.md)
target model, so the change manifest for a journey is **computed from the
document**, exactly as it is for a plan's `FileSystem` or `Registry` steps.

| Verb | Kind | Verb | Target name |
|---|---|---|---|
| `open_app` | `ui` | `create` | the application |
| `focus_window`, `resize_window` | `ui` | `invoke` | the window |
| `close_window` | `ui` | `delete` | the window |
| `navigate` | `host` | `reach` | the URL's host |
| `click`, `double_click`, `right_click` | `ui` | `invoke` | the selector |
| `invoke`, `expand`, `collapse` | `ui` | `invoke` | the selector |
| `toggle`, `select` | `ui` | `write` | the selector |
| `set_value`, `type_text`, `clear` | `ui` | `write` | the selector |
| `enter_credential` | `ui` | `write` | the selector |
| `press_keys` | `ui` | `execute` | `keyboard: <chord>` |
| `hover`, `scroll`, `read`, `observe`, `capture` | `ui` | `read` | the selector, or `screen` |
| `pause` | — | — | derives nothing |

Selector names render as the accessible name, or as `(x,y)` for a point target —
which is what makes a coordinate-targeted step visible in the manifest without
reading the document.

Two properties follow, and they are the whole point of the exercise:

- **Derivation is total.** Every verb derives, so a journey's manifest is complete
  by construction. The behaviour being replaced derived nothing for any UI tool, so
  a journey's manifest was empty and every step rendered as non-destructive —
  which is to say the manifest was not merely uninformative but wrong.
- **There is nothing to declare, so nothing to understate.** A plan step may
  declare targets, and the plan validator checks the declaration does not omit what
  the tool provably touches. A journey has no such field and needs none: the
  document *is* the declaration, and the derivation reads it directly.

`navigate` additionally passes through the `enforce_https` policy setting, like
every other URL entry point.

---

## 8. What `journey validate` checks, with no desktop

The whole taxonomy is checkable offline, which is the practical reason for
closing it. `journey validate` runs in CI on any platform and checks:

1. `version` is 2, and no unknown fields appear anywhere.
2. Every `verb` is in the set of §3.
3. Every verb's parameters are present, correctly typed, and no parameter belongs
   to a different verb.
4. Every selector is well-formed: exactly one of `automation_id` / `name` /
   `point`; a legal `occurrence` and `scope`; `name_match` present only alongside
   `name`, and a `matches` name pattern that compiles.
5. Every verb that requires a target has one, and none that forbids a target
   carries one.
6. Every `subject` and `operator` is in the set of §5, and the pair is legal per
   the matrix of §5.3.
7. `expected` is present exactly when the operator takes one, and is of the right
   type for the subject.
8. Every regex compiles and is within the length cap.
9. `wait.timeout` and `wait.interval` are within bounds.
10. A `result.text` assertion is preceded by a `read` in the same journey.
11. Every `expected_evidence` label is produced by some step.

Every problem is reported at once, so a file is fixed in one pass rather than one
run at a time.

The behaviour this replaces could check almost none of it. A journey step named a
tool and carried an untyped argument map, and the package that validates journeys
is deliberately platform-agnostic while the tool definitions are Windows-only — so
the validator could not see a tool's schema, and a misspelled tool name or a
missing required argument passed validation and failed on the desktop, after
earlier steps had already changed it. Typed verbs remove the dependency
altogether: the vocabulary validates against itself.

---

## 9. Deliberately not covered

Stated so they are not re-litigated:

- **Control flow.** See §1. Conditionals and loops would make a journey a program,
  and a program's reach cannot be derived from its text — which is the property
  everything here is built on.
- **Variables and expressions**, beyond the single `result.text` register. A
  templating language reintroduces exactly the unbounded evaluation a closed
  vocabulary exists to exclude.
- **Structural selectors.** See §4.3.
- **Soft assertions** (record a failure and carry on). A journey fail-stops
  because desktop actions have no rollback: continuing past a failed assertion
  means acting on a screen you have just proved you do not understand.
- **Parallel steps.** The desktop is a single shared surface and the engine
  serialises everything onto one COM thread; concurrency would be a lie told at
  the document level.
- **Vision-based targeting.** The accessibility-tree-only design is deliberate and
  is a data-residency argument: desktop pixels never leave the machine.
