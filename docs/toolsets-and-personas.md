# Toolsets and personas

What each tool does, how to select a subset, and what "customising a persona"
actually means.

- [Toolset reference](#toolset-reference)
- [Choosing a selection](#choosing-a-selection)
- [Personas](#personas)
- [Customising](#customising)
- [What SYSTEM changes](#what-system-changes)

---

## Toolset reference

Ten toolsets. Four are on by default; the rest are opt-in because they reach
further than looking at the screen.

### `screen` — default

| Tool | Does |
|---|---|
| `Snapshot` | The foreground window plus a labeled tree of interactive elements. The perception primitive — most loops start here |
| `Screenshot` | A PNG of the entire virtual desktop (all monitors) |
| `DisplayInventory` | Connected displays: bounds, work area, DPI, scale |
| `Recording` | Session-recording status, and timeline markers |

### `interaction` — default

| Tool | Does |
|---|---|
| `Invoke` | Acts through a UI Automation control pattern — invoke, set_value, toggle, select, expand/collapse. **Prefer this** |
| `Click` | Synthetic mouse click |
| `Type` | Synthetic keystrokes |
| `GetText` | Reads an element's text or value |
| `Scroll`, `Move`, `Shortcut` | Wheel, pointer move, key chords |
| `Wait`, `WaitFor` | Fixed delay; wait for a condition — `active_window`, `element_exists`, `text_exists` |
| `MultiSelect`, `MultiEdit` | Batch selection and batch field entry |

### `apps` — default

| Tool | Does |
|---|---|
| `App` | Launch by name, launch an executable, switch to, resize/move a window |

### `system` — default

| Tool | Does |
|---|---|
| `Clipboard` | Get or set clipboard text |
| `Process` | List and terminate processes |
| `Registry` | Read and write registry values — **destructive** |
| `Notification` | Raise a Windows toast |

### `shell` — opt-in

| Tool | Does |
|---|---|
| `PowerShell` | Runs an arbitrary command — **destructive, full system access** |

### `filesystem` — opt-in

| Tool | Does |
|---|---|
| `FileSystem` | read / write / copy / move / delete / list / search / info — **destructive** |

### `web` — opt-in

| Tool | Does |
|---|---|
| `Scrape` | Fetches a URL and returns text. Subject to `enforce_https` |

### `diagnostics` — opt-in

| Tool | Does |
|---|---|
| `SystemInfo` | OS, hardware, memory and disk inventory via WMI |
| `Service` | List / start / stop / restart Windows services — **destructive** |

Also carries the `windows://system/info` resource and the `triage-support-issue`
prompt.

### `testing` — opt-in

| Tool | Does |
|---|---|
| `Assert` | PASS/FAIL a UI condition — `text_present`, `element_present`. The verification primitive for journeys. (Note the condition names differ from `WaitFor`'s) |
| `CaptureEvidence` | Screenshot plus accessibility tree, labeled |

Also carries the `capture-evidence` prompt.

### `planning` — opt-in

| Tool | Does |
|---|---|
| `Plan` | Propose a whole sequence of tool calls; returns a change manifest and a plan id. Changes nothing |
| `Apply` | Execute a proposed plan by id — verbatim, posture re-checked, fail-stop. See [Plan and apply](plan-and-apply.md) |

### `credentials` — opt-in

| Tool | Does |
|---|---|
| `Credentials` | list / verify / inject. Never returns a secret — see [Credentials](credentials.md) |

Enabled automatically by `--credentials-file`, **additively** — your other
toolsets are kept.

### Always served

`GuardrailStatus` and `Kill` belong to no toolset and are present under every
persona and every selection. They are the agent's read-only view of the security
posture and its way to stop the session. Neither can actuate containment the
policy did not configure.

---

## Choosing a selection

Four knobs, applied in this order:

```sh
--persona qa-test-engineer          # a named preset: toolsets + read-only stance + instructions
--toolsets screen,interaction,web   # explicit toolsets; 'all' and 'default' are special
--tools GetText,Assert              # add individual tools, bypassing toolset filtering
--exclude-tools PowerShell,Registry # remove specific tools, applied last
```

`--exclude-tools` always wins. Use it to carve a dangerous tool out of an
otherwise convenient toolset:

```sh
# everything except the shell
windows-mcp-server.exe stdio --toolsets all --exclude-tools PowerShell
```

`--read-only` exposes only tools annotated read-only. It is the blunt instrument;
a persona's own stance is usually better, and note that passing `--read-only`
explicitly overrides a persona's stance in either direction. `--tools` does **not**
escape `--read-only`: a write tool added there is still filtered.

`--tools` bypasses toolset filtering, which is fine when you are composing a
surface by hand — but a **persona is a documented guarantee** about what is
served. So `--tools` naming a tool outside the active persona's toolsets is
**refused at startup** rather than silently widening the persona. Select
`--toolsets` explicitly instead of a persona if you want to add to that set.

### Resources and prompts follow their toolset

This surprises people: resources and prompts are filtered like tools.

| Surface | Toolset | Present by default? |
|---|---|---|
| `windows://desktop/snapshot` | screen | Yes |
| `windows://desktop/displays` | screen | Yes |
| `windows://session/recording` | screen | Yes |
| `windows://system/info` | diagnostics | **No** |
| `rpa-journey` prompt | interaction | Yes |
| `triage-support-issue` prompt | diagnostics | **No** |
| `capture-evidence` prompt | testing | **No** |

So `business-user` (no diagnostics) serves no `triage-support-issue`, and
`first-line-support` (no testing) serves no `capture-evidence`. If a prompt you
expect is missing, check whether its toolset is enabled.

---

## Personas

A persona is a preset over one manifest: a toolset selection, a read-only
stance, and instructions text injected into the server's own instructions so the
model adopts that workflow. **Adding a persona never adds tools.**

```sh
windows-mcp-server.exe personas          # list them
windows-mcp-server.exe stdio --persona qa-test-engineer
```

| Persona | Toolsets | Built for |
|---|---|---|
| `first-line-support` | screen, interaction, apps, system, shell, diagnostics | Diagnose before acting — `SystemInfo`, `Process`, `Service`, PowerShell |
| `qa-test-engineer` | screen, interaction, apps, system, filesystem, web, testing | Deterministic UI tests — label targeting, `Assert`, `CaptureEvidence` |
| `business-user` | screen, interaction, apps, web, testing | End-user journeys through the real UI. No shell, registry or filesystem |

The workflow prompts build their text from the matching persona's instructions
rather than restating it, so `--persona` and the prompts cannot drift apart.

---

## Customising

**Personas are compiled in.** They live in `pkg/windows/toolsets.go`; there is no
file or flag that adds one. Changing a persona means editing that map and
rebuilding.

For anything short of that, compose the flags instead — it covers most of what
people want a custom persona for:

```sh
# business-user, but with filesystem for evidence handling
windows-mcp-server.exe stdio --persona business-user --toolsets screen,interaction,apps,web,testing,filesystem

# qa-test-engineer minus the destructive tools
windows-mcp-server.exe stdio --persona qa-test-engineer --exclude-tools Registry,FileSystem
```

If you do add a persona in a fork, `pkg/inventory` is domain-agnostic and does
the filtering; the persona map and the toolset constants are the only things you
need to touch.

---

## What SYSTEM changes

If the server runs as SYSTEM (Session 0), it **cannot drive a desktop** — there
is no interactive session to automate. This is detected, not declared, and the
toolset selection is replaced wholesale:

```
system, shell, filesystem, diagnostics, web
```

Two consequences worth knowing:

- **A persona explicitly requested under SYSTEM is refused.** The server exits
  with an error rather than serving a reshaped version of it — so a scripted
  deployment that asks for `business-user` and lands in Session 0 fails loudly
  instead of quietly serving shell and filesystem.
- **Without a persona, the replacement is applied and announced.** The server
  warns at startup and raises a toast, so the reduced surface is visible.

Credentials are also not auto-enabled under SYSTEM.

---

## Related

- [Getting started](getting-started.md) — first run and client setup
- [Policy configuration](policy-config.md) — gating tools on device posture
- [Credentials](credentials.md) — the `credentials` toolset
