# Credentials

Let the agent sign in to applications and websites without ever putting a secret
in its context.

Credentials are supplied at startup and installed into the Windows Credential
Manager for the running user. Anything in that user context — a browser, a
line-of-business app, RDP, a mapped drive, Windows SSO — consumes them the normal
way. The agent asks for a credential *by name*; it never receives the value.

- [Setting it up](#setting-it-up)
- [Securing the file](#securing-the-file)
- [Using it from the agent](#using-it-from-the-agent)
- [What the design guarantees](#what-the-design-guarantees)

---

## Setting it up

### 1. Write the file

```json
{
  "credentials": [
    {
      "name": "corp-sso",
      "target": "login.contoso.com",
      "username": "svc-automation@contoso.com",
      "secret": "…",
      "comment": "optional note stored on the credential"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `name` | The handle the agent uses. Keep it descriptive — this is what appears in prompts and the audit log |
| `target` | The Credential Manager target. For web sign-in this is usually the host |
| `username` | Stored alongside the secret |
| `secret` | The value. Never leaves the machine, never reaches the agent |
| `type` | `generic` (default) or `domain_password` |
| `comment` | Optional note stored on the credential |

### 2. Put it somewhere only you can read

`%ProgramData%` is a reasonable home for a service deployment; a path under your
own profile is fine for a desktop one. What matters is the ACL, not the location.

### 3. Point the server at it

```powershell
.\windows-mcp-server.exe stdio --credentials-file C:\ProgramData\windows-mcp\creds.json
```

This enables the `credentials` toolset **additively** — your existing toolsets
are kept, not replaced.

---

## Securing the file

The server reads the file's **real DACL** at startup and refuses to run if any of
these can read it:

- `Everyone`
- `BUILTIN\Users`
- `NT AUTHORITY\Authenticated Users`
- `NT AUTHORITY\INTERACTIVE`
- or the file has a NULL DACL (everyone has full control)

A Unix permission check would prove nothing here — Windows synthesizes `0666` for
every normal file, so `Mode().Perm()` is meaningless. The real ACL is the only
thing worth checking.

### Creating a compliant file

Break inheritance, drop the broad groups, and grant only yourself and SYSTEM:

```powershell
$file = "C:\ProgramData\windows-mcp\creds.json"

icacls $file /inheritance:r
icacls $file /grant:r "$($env:USERDOMAIN)\$($env:USERNAME):(R)"
icacls $file /grant:r "NT AUTHORITY\SYSTEM:(F)"
icacls $file /grant:r "BUILTIN\Administrators:(F)"
```

Check what you ended up with:

```powershell
icacls $file
```

If startup still refuses, the message names the offending principal and prints
the `icacls` command to fix it.

---

## Using it from the agent

Three modes, and deliberately no fourth:

```jsonc
// What is available, plus whether each is present in the store right now.
// Identifiers only — never secrets.
{"mode": "list"}

// Confirm a credential resolves without using it.
{"mode": "verify", "name": "corp-sso"}

// Type the secret at the current focus.
{"mode": "inject", "name": "corp-sso"}

// Click a field first, then type, then submit.
{"mode": "inject", "name": "corp-sso", "label": 7, "press_enter": true}

// Or target the field by name.
{"mode": "inject", "name": "corp-sso", "name_target": "Password", "control_type": "Edit"}
```

A typical sign-in journey: `Snapshot` to find the form, `Type` the username (or
`inject` a credential whose username you also want typed), `inject` into the
password field, `Assert` that you landed where you expected.

### `domain_password` cannot be injected

Windows does not return a domain-password blob to a caller, so these are
installed for Windows to *use* — SSO, mapped drives, RDP — but cannot be typed.
`list` reports them as `injectable: false` rather than failing opaquely when you
try.

---

## What the design guarantees

**The agent can use a secret but never read one.** This is the property the whole
design is built around:

- **No mode returns plaintext.** There is deliberately no `get`. A unit test pins
  the mode set, so a secret-reading mode cannot be added by accident.
- **`inject` types keystrokes.** The value is read inside the desktop engine,
  converted straight to synthetic input, and the buffers zeroed. Only the
  character count comes back. The secret never enters a tool result, the audit
  log, the transcript, or the model's context.
- **No function in the engine returns a secret.** The read path returns UTF-16
  code units rather than a string, specifically so a refactor cannot hand one to
  a caller.
- **Audit records identifiers only** — name, target, username, class — via
  `credentials.installed` and `credentials.removed`.

### Lifecycle

- **Secrets are never accepted as flags.** `argv` is readable by any process on
  the machine. The file is the only supply path.
- **Installed only after admission.** A startup blocked by policy never
  provisions credentials, and a partial install is rolled back.
- **Session-scoped.** Entries are written with `CRED_PERSIST_SESSION` and deleted
  on *every* shutdown path — normal exit and kill-switch trip alike. Durable
  persistence is refused rather than silently overridden.
- `Credentials` is **not** annotated destructive — it is annotated
  `ReadOnlyHint: false`, because `inject` synthesizes input. A rate limit or rule
  matching `annotation: destructive` therefore does **not** cover it. Match it by
  name (`"tool": "Credentials"`) or by toolset if you want to gate it.

> Secrets exist in process memory between reading the file and installing them.
> Buffers are zeroed and the JSON decoder avoids materializing an unwipeable Go
> string for unescaped values, but Go offers no guarantee that no copy was made.
> Treat the host as trusted.

---

## Related

- [Policy configuration](policy-config.md) — gating `Credentials` behind device posture
- [Security architecture](security-architecture.md#credentials--use-without-disclosure) — the design rationale
- [Monitoring](monitoring.md) — the `credentials.*` audit events
