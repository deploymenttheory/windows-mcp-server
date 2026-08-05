# Plan and apply

The usual loop is one call at a time: the agent calls a tool, the policy engine
decides it, it runs. That is how a sequence of individually-benign calls can add
up to something you would not have approved as a whole.

**Plan-and-apply** closes that gap. The agent proposes a *whole* sequence of tool
calls; the engine adjudicates all of it up front and returns a change manifest;
only then, on a separate call, is it executed. It is the `terraform plan` / `apply`
shape, for desktop automation.

It is an **opt-in toolset** (`planning`), off by default — a distinct way of
working, not an extra tool for the usual loop.

```powershell
windows-mcp-server.exe stdio --toolsets default,planning
```

## The two tools

- **`Plan`** — submit a plan (a `version` and an ordered list of `steps`, each a
  `tool` and its `args`). It changes nothing: it validates the plan, evaluates the
  whole thing against current device posture, and returns a **change manifest**
  and a `plan_id`.
- **`Apply`** — run a plan by its `plan_id`. It re-checks posture, then executes
  the steps in order, **stopping at the first that fails or is refused**.

```jsonc
// Plan
{ "version": 1, "steps": [
  { "name": "read config", "tool": "FileSystem", "args": { "mode": "read", "path": "C:\\app\\config.json" } },
  { "name": "restart", "tool": "PowerShell", "args": { "command": "Restart-Service Spooler" } }
] }
```

```
Plan 62cd34800b7e — 2 step(s)
  1. read config [FileSystem]
       file     read    C:\app\config.json
  2. restart [PowerShell] ⚠ destructive ⚠ undeclarable blast radius
       shell    execute PowerShell command
Summary:
  file: 1
  shell: 1
  1 of 2 step(s) destructive, 1 with an undeclarable blast radius
Verdict: warn (admitted)
Apply with plan_id 62cd34800b7e...
```

## The change manifest

The manifest is what the plan will **touch**, grouped by kind (file, registry,
process, host, ui, package, task, shell) and annotated. It is a declared-and-
derived change *list*, not a before/after state *diff* — reading current state to
build a diff would itself be an action the session may not be allowed to take.

For every step the server **derives** the reach from the tool and its arguments
(a `FileSystem` write is a file written, an `App` launch of a URL is a host
reached), independently of what the agent claims — so a plan cannot **understate**
what it does. `PowerShell` is the exception: its reach cannot be read from a
command string, so it is flagged **undeclarable** and treated as destructive.

## Governance: what runs versus what was approved

`Apply` runs the plan **verbatim** — each step's arguments come from the stored,
approved plan, *not* from the `Apply` call, which carries only the `plan_id`. So
within an apply, **what executes is exactly what was approved, by construction**:
the agent cannot mutate a step's arguments or order between approval and execution.
The `plan_id` is the SHA-256 of the plan's content, so any change to the plan is a
different id.

Every stage is on the [audit chain](monitoring.md): `plan.proposed` (the plan id,
each step's tool and argument digest, and the verdict), a `plan.step` per executed
step, and `plan.applied` (completed / failed / skipped). Because `Apply` bypasses
the per-call middleware to run steps directly, a step produces a `plan.step` and
**no** free-standing `tool.call` — which is exactly what makes a **direct call
made outside a plan** distinguishable after the fact: it is a `tool.call` with no
owning `plan.step`.

Plan-and-apply has two strictness tiers, chosen per tool by policy:

- **Detective** (the default): direct out-of-plan calls are allowed but recorded,
  so you can prove after the fact whether the agent honoured a plan. Use this to
  watch how the model actually behaves before deciding what to clamp down.
- **Preventive**: a `require_plan` policy selector names the tools that may only
  run inside an approved plan. A **direct** call to a matching tool is refused
  (`plan.required`) and the model is told to submit it via Plan; the same tool
  runs normally as a *step* of a plan, because plan steps are executed by the
  planner and never pass through the enforcement gate.

```jsonc
"require_plan": [
  { "annotation": "destructive" },   // anything destructive must be planned
  { "toolset": "shell" }             // and all shell use
]
```

The selector uses the same `tool` / `toolset` / `annotation` match a rule does.
The planning tools themselves are always exempt — you cannot require a plan to
make a plan. The full approved plan document is captured into the signed evidence
bundle, which is the artifact a reviewer opens to compare intent against what ran.

## What Apply guarantees

- **Posture re-check.** The whole plan is re-adjudicated against live signals
  before the first step; if posture has drifted so the plan is no longer admitted,
  the apply is refused and audited `plan.refused`.
- **Per-step evaluation.** Each step is evaluated again at the moment it runs —
  apply is an extra gate, never a bypass — and this is the decision that counts
  against rate limits (planning does not spend rate-limit budget).
- **Fail-stop.** The first step that fails or is refused halts the apply; desktop
  actions have no rollback, so the record lists what completed, failed and was
  skipped rather than pretending the sequence was transactional.
- **Containment-aware.** If the kill switch trips mid-apply, the remaining steps
  are abandoned and the partial record is sealed.

A plan may not contain `Plan` or `Apply` steps, and every step's tool must be one
the current surface serves — both checked when the plan is proposed.

## Journeys are plans

A [journey](journeys.md) is a pre-authored plan with assertions and evidence
interleaved, compiled from a closed verb vocabulary rather than written as tool
calls. It runs through this same executor and inherits everything above.

The division is worth keeping in mind when choosing between them. A plan is
general: any served tool, an untyped `args` map, usually composed by the agent,
and reach that is derived where it can be derived — `PowerShell` being the case
where it cannot. A journey is narrow: a closed set of UI verbs with typed
parameters, usually written by a person or drafted by the recorder, and reach
that is **always** derivable because the vocabulary is closed. Anything needing a
shell, the registry or the filesystem is a plan.
