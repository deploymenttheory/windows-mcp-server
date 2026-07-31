# Remote signals: Graph and may-run

Two signal families come from off the machine rather than from it. They are the
only ones a local administrator cannot spoof, which is what makes them worth the
setup.

- [Microsoft Graph](#microsoft-graph) — Entra and Intune compliance
- [External may-run endpoint](#external-may-run-endpoint) — your own policy decision point

They register differently, and it matters:

- **The Graph signals exist only when Graph is configured.** Without the
  environment variables below they are not in the registry at all, and a policy
  naming one is **refused at load** — `signals.graph-intune-compliant is not a
  signal this build can evaluate`. That is deliberate: a policy whose author
  believes Graph is gating the device must not start on a machine where it
  cannot be read.
- **`remote-policy` is always registered.** The token merely adds an
  `Authorization: Bearer` header. A policy requiring it on a machine with no
  token still loads, and the check fails or errors at evaluation time.

> Credentials come from the environment, never from flags or the policy
> document. `argv` is world-readable, and the policy is meant to be reviewable
> and checked in.

---

## Microsoft Graph

Five signals, each asking Entra or Intune about *this* device:

| Signal id | Asks |
|---|---|
| `graph-entra-registered` | Does the device exist in Entra ID? |
| `graph-entra-compliant` | Does Entra report it compliant? |
| `graph-intune-enrolled` | Is it enrolled in Intune? |
| `graph-intune-compliant` | Does Intune report it compliant? |
| `graph-attested` | Does Intune hold a health-attestation record? |

Write the id you want — there is no `graph-*` wildcard, and a name this build
does not know is refused at load.

### How the device is identified

The server reads the Entra device ID from `dsregcmd` and queries Graph for that
specific device. If the machine is not Entra-joined or registered, there is no id
to query with and these signals cannot pass.

### App registration

1. **Entra admin center → App registrations → New registration.** Single tenant
   is fine. No redirect URI — this is a daemon flow.
2. **Certificates & secrets → New client secret.** Record the value; it is shown
   once.
3. **API permissions → Microsoft Graph → Application permissions:**

   | Permission | For |
   |---|---|
   | `Device.Read.All` | The `graph-entra-*` signals |
   | `DeviceManagementManagedDevices.Read.All` | The `graph-intune-*` and `graph-attested` signals |

   Application permissions, not delegated — there is no signed-in user.
4. **Grant admin consent.** Without it the app is registered and every call
   returns 403.

Read-only permissions throughout. The server never writes to Graph.

### Configure the server

```powershell
$env:WINDOWS_MCP_GRAPH_TENANT        = "contoso.onmicrosoft.com"   # or the tenant GUID
$env:WINDOWS_MCP_GRAPH_CLIENT_ID     = "…"
$env:WINDOWS_MCP_GRAPH_CLIENT_SECRET = "…"
```

For a scheduled-task deployment, set these on the task rather than machine-wide,
so they are not readable by every process on the box.

Then declare the signals and require them:

```jsonc
{
  "signals": {
    "graph-intune-compliant": { "ttl": "5m" }
  },
  "rules": [
    { "name": "managed-device", "match": { "toolset": "*" },
      "require": ["graph-intune-compliant"], "on_fail": "deny" }
  ]
}
```

A TTL of minutes is right here — these are network calls, and compliance state
does not change second to second.

### Verify

```powershell
.\windows-mcp-server.exe policy check --policy-config policy.json
```

`check` reads every declared signal live, cache bypassed, and exits 2 if the
device is not admitted. If the Graph signals error rather than fail, the cause is
usually consent not granted, or a tenant/client mismatch.

> The queries use Graph's `beta` endpoint, which Microsoft may change without
> notice. Pin your expectations to the signals, not to the payloads.

---

## External may-run endpoint

`remote-policy` asks a service you control whether this device may run, right
now. It is the escape hatch for policy that cannot be expressed as device
signals — a maintenance window, a per-device allowlist held elsewhere, a
break-glass switch.

### The contract

The server POSTs JSON and expects a decision back:

```jsonc
// Request
{
  "device":      { "hostname": "…", "serial": "…" },
  "run_context": { "is_system": false, "session_id": 1, "elevated": false, "user": "…" },
  "hostname":    "…"
}
```

```jsonc
// Response — either shape is accepted
{ "allow": true,  "reason": "within maintenance window" }
{ "result": { "allow": false, "reason": "device quarantined" } }
```

The nested `result` form exists so an OPA-style PDP can be used without a shim.

`reason` is surfaced in the decision and the audit log, so make it something an
operator can act on.

### Configure

The URL goes in the policy document as the signal's `arg`; the bearer token goes
in the environment:

```jsonc
{
  "signals": {
    "remote-policy": { "ttl": "60s", "arg": "https://policy.contoso.com/may-run" }
  },
  "rules": [
    { "name": "central-authority", "match": { "toolset": "*" },
      "require": ["remote-policy"], "on_fail": "deny" }
  ]
}
```

```powershell
$env:WINDOWS_MCP_REMOTE_POLICY_TOKEN = "…"
```

### HTTPS is not optional here

With `"enforce_https": true`, a plaintext may-run endpoint **fails the signal**
rather than being skipped. The request carries device identity and a bearer
token, so plaintext would disclose both — failing is the only honest answer.

### Choosing a TTL

This is the one signal where a short TTL is often worth the cost, because it is
how you revoke a running session centrally. At `"ttl": "60s"`, flipping the
endpoint's answer stops the device acting within a minute; the in-flight monitor
re-evaluates in the background, so there is no restart.

`"ttl": "0s"` makes it live on every call. Only do that if the endpoint is fast
and highly available — every tool call then depends on it.

---

## Related

- [Policy configuration](policy-config.md) — the signals table and rule syntax
- [Deployment](deployment.md) — setting environment variables on a scheduled task
- [Security architecture](security-architecture.md#trust-model) — why remote signals are the authoritative ones
