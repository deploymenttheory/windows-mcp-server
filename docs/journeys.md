# Journeys as code

> **Status: design.** This describes journey schema **version 2**, which is not yet
> implemented — the `verb` vocabulary, the selector rules and the
> `subject`/`operator` assertions below are the target, not the shipped build. The
> current build accepts version 1: a step names an MCP tool and carries an untyped
> `args` map, and assertions are one of seven fixed `kind`s. `roadmap.md` tracks
> the implementation phases.

A **journey** is a named sequence of user actions, each with assertions about the
resulting screen and evidence to capture — a login smoke test, an expense-claim
regression — written as JSON and run deterministically, rather than as a prose
script a human follows by hand.

This is the authoring guide. The vocabularies it uses are defined in the
[journey taxonomy](journey-taxonomy.md), which is normative; what a run records is
defined in [journey evidence](journey-evidence.md).

A journey **compiles to a [plan](plan-and-apply.md)** and runs through the same
executor `Apply` uses: every step is evaluated by the policy engine, audited, and
**fail-stopped** on the first failure. A failed assertion is a failed step — the
run stops there and reports it, exactly as a test runner would.

## A document

```jsonc
{
  "version": 2,
  "name": "expenses-submit",
  "description": "Submit an expense claim and confirm the reference number.",
  "steps": [
    {
      "name": "open the expenses app",
      "verb": "open_app",
      "app": "Contoso Expenses",
      "assertions": [
        { "subject": "window.title", "operator": "contains", "expected": "Expenses",
          "wait": { "timeout": 20 } }
      ],
      "evidence": [ "app opened" ]
    },
    {
      "name": "enter the amount",
      "verb": "set_value",
      "target": { "name": "Amount", "control_type": "Edit" },
      "value": "126.40"
    },
    {
      "name": "submit the claim",
      "verb": "click",
      "target": { "name": "Submit", "control_type": "Button" },
      "assertions": [
        { "subject": "element", "target": { "name": "Reference", "control_type": "Text" },
          "operator": "exists", "wait": { "timeout": 30 },
          "message": "the confirmation panel appears" }
      ]
    },
    {
      "name": "read the reference",
      "verb": "read",
      "target": { "name": "Reference", "control_type": "Text" },
      "assertions": [
        { "subject": "result.text", "operator": "matches", "expected": "EXP-[0-9]{6}",
          "message": "the reference is well-formed" }
      ],
      "evidence": [ "claim submitted" ]
    }
  ],
  "expected_evidence": [ "claim submitted" ]
}
```

- **`verb`** and its parameters — the action, from the closed set in
  [§3 of the taxonomy](journey-taxonomy.md#3-verbs). A journey never names an MCP
  tool; the compiler decides which call expresses the verb.
- **`target`** — which element or window, per
  [§4](journey-taxonomy.md#4-selectors). Exact and unambiguous by default.
- **`assertions`** — conditions checked *after* the action, as
  `subject` × `operator` × `expected` per [§5](journey-taxonomy.md#5-assertions).
  A failing one fails the step and stops the journey.
- **`evidence`** — captions for evidence to capture at that point.
- **`expected_evidence`** — labels a passing run must produce. Checked at validate
  time (some step must produce each) *and* after the run (the run must actually
  have captured each).

Unknown fields are rejected, so a typo in a key fails at `validate`.

## Writing one that does not flake

Four habits, each of which the taxonomy makes cheap:

**Assert, don't sleep.** Put a `wait` on the assertion that states what you are
waiting *for*, rather than a `pause` step guessing how long it takes. The run
record then tells you it took 14.6 seconds of its 15-second budget, which is a
warning you can act on before it becomes a failure.

```jsonc
// prefer
{ "subject": "element.enabled", "target": { "name": "Submit" },
  "operator": "is_true", "wait": { "timeout": 15 } }

// over
{ "verb": "pause", "seconds": 5 }
```

**Target by name, and let ambiguity fail.** `occurrence` defaults to `unique`, so
a selector matching two controls fails and names both, rather than picking one.
When you genuinely mean the second one, say `"occurrence": 1` — the document then
records that you knew.

**Prefer `set_value` and `invoke` over `type_text` and `click`.** They go through
UIA patterns rather than synthetic input, so they do not depend on window focus
and cannot be stolen by a notification popping up mid-run. Fall back to the input
verbs only for controls that expose no pattern.

**Assert what you read, not just what you see.** `read` puts a control's text into
the run's register; a `result.text` assertion checks it. That is how you verify a
generated reference number, a total, or a status string, rather than checking that
*something* appeared.

## Running

```powershell
# Offline — parse, validate, compile to a plan. No desktop needed; put this in CI.
windows-mcp-server journey validate journeys/examples/expenses-submit.json

# Live — run against the real desktop and report pass/fail. Exits 1 on failure.
windows-mcp-server journey run journeys/examples/expenses-submit.json --policy-config policy.json
windows-mcp-server journey run journeys/examples/expenses-submit.json --json   # for CI
```

`validate` checks everything in
[§8 of the taxonomy](journey-taxonomy.md#8-what-journey-validate-checks-with-no-desktop)
— verbs, parameters, selectors, the subject/operator matrix, regex compilation,
evidence expectations — and reports every problem at once. It needs no Windows
host and no desktop, so a broken journey fails in CI rather than on the machine
that was going to run it.

`run` requires an interactive desktop; on a machine that cannot host UI automation
it errors rather than reporting a spurious pass. The whole run is recorded on the
audit chain — `journey.started`, a `plan.step` per action and assertion, and
`journey.finished` with the counts — and produces the run record described in
[journey evidence](journey-evidence.md).

The testing toolset is served automatically for a journey run, so a journey's
assertions and evidence work regardless of the rest of the toolset selection.

## Don't write it — record it

Almost nothing above is meant to be typed by hand. Forty steps of JSON is not an
authoring experience, and a journey vocabulary that only a determined author can
produce would get used twice and abandoned. The recorder is the **primary author**:

```powershell
windows-mcp-server journey record --out journeys/expenses-submit.json --name expenses-submit
# do the task; F8 marks an assertion; F9 stops
```

It installs low-level input hooks and captures what you do, resolving each click
to the element under it — picking the most stable selector available and checking
it against the live tree, which is something a hand-written selector can never
be — inferring the verb from what that element supports, and **redacting password
fields**, which are never written to the file.

The result is a **reviewable draft**, because a recorder captures actions and only
you know intent. Assertions are where that shows most: a perfect capture of a
human submitting an expense claim proves the clicks landed and notices nothing
about the total being wrong. There are three ways a recording acquires
assertions — marking them as you go, accepting proposals from what changed after
each action, and freezing a golden run — and they are the subject of
[recording a journey](journey-recording.md), along with why the recorder is a CLI
verb and never an MCP tool.

Recording needs an interactive desktop. On a US keyboard the character mapping is
exact; other layouts fall back to the base character or a named key.

## Relationship to plans

A journey **is** a pre-authored plan plus interleaved assertions and evidence, so
it inherits every property of [plan-and-apply](plan-and-apply.md): whole-plan
adjudication before anything runs, per-step live policy evaluation at execution,
fail-stop, and abandonment on a kill-switch trip. A journey step that hits a
policy `deny` — or a `hold` that is not approved — refuses and stops the run, the
same as any plan step.

The division of labour between the two is deliberate:

| | Journey | Plan |
|---|---|---|
| Vocabulary | closed verb set | any served tool |
| Arguments | typed per verb | untyped `args` map |
| Written by | a person, or the recorder | usually the agent |
| Reach | derived from the document, always complete | derived where derivable; `PowerShell` is undeclarable |
| For | user journeys through a UI | anything else |

Anything needing a shell, the registry or the filesystem is a plan. That boundary
is what lets a journey promise that every step is an attested verb.

## Version 2

Version 1 documents are **not** accepted, and there is no conversion. A v1 step
named an MCP tool and carried an untyped `args` map, which is exactly what the
taxonomy replaces; converting one mechanically would produce a v2 document that
still could not be checked. Rewrite the journeys you have against
[§3 of the taxonomy](journey-taxonomy.md#3-verbs), or re-record them.
