# Shipping evidence off the device

An [evidence bundle](evidence-bundles.md) is the artifact you hand to an auditor:
a session's audit chain, its verdicts, the plan documents, the journey run records
and screenshots, and the recording — sealed into one self-verifying, optionally
signed archive. Sealing it is only half the job. The bundle lands in
`transparency.evidence_dir`, which is a directory on the same machine the session
ran on, and an on-box adversary, a reimaged VM or a routine disk wipe takes it
with them.

`transparency.export` ships that bundle to cloud blob storage as the session
exits. It is the fourth transparency destination, and it follows the same argument
as [anchoring](monitoring.md): the anchor publishes the chain *head* somewhere the
session cannot reach back into, and this publishes the whole artifact.

```jsonc
"transparency": {
  "audit_destination": "C:\\ProgramData\\windows-mcp\\audit\\",   // must be a directory
  "evidence_dir":      "C:\\ProgramData\\windows-mcp\\evidence",
  "export": {
    "provider": "signed_url",
    "timeout":  "5m"          // optional; defaults to 2m
  }
}
```

Export is **off unless a provider is named**, and that is deliberate: a server
that began shipping a session's evidence off-box on upgrade, with no operator
action, would be the same class of regression as one that began refusing tool
calls.

## What is shipped

Three objects per session:

| Object | Contents |
|---|---|
| `session-<stamp>.evidence.zip` | The sealed bundle |
| `session-<stamp>.manifest.json` | The bundle's manifest — every member with its size and SHA-256, the session stamp, and the audit chain head |
| `session-<stamp>.manifest.sig` | The detached ed25519 signature, when the bundle is signed |

The sidecars are already inside the archive. They travel beside it so a reviewer
can check provenance from an object listing — *is this the bundle that device
sealed, and was it signed by the key we published?* — without downloading a
recording-sized archive to find out.

They are read back **out of the sealed bundle** rather than kept from the sealing
step, so the sidecar bytes are provably the same bytes the manifest was hashed and
signed over, not a second rendering of the same struct that could drift from it.

The bundle is uploaded first. A destination that accepts one object and then fails
still has the artifact that matters.

## Destinations

### `signed_url` — no principal on the device

The operator mints a URL out of band and puts it in the environment. An S3
pre-signed PUT, an Azure SAS blob URL and a GCS V4 signed URL are all the same
operation — *PUT these bytes here* — so one backend covers all three clouds with
no SDK and no credential chain.

```powershell
$env:WINDOWS_MCP_EXPORT_SIGNED_URL = "https://acme.blob.core.windows.net/evidence/session-20260805-120000.evidence.zip?sv=..."
# optional; without them only the bundle ships
$env:WINDOWS_MCP_EXPORT_SIGNED_URL_MANIFEST  = "https://.../session-20260805-120000.manifest.json?sv=..."
$env:WINDOWS_MCP_EXPORT_SIGNED_URL_SIGNATURE = "https://.../session-20260805-120000.manifest.sig?sv=..."
```

A signature covers a **single object name**, which is the trade-off: there is no
prefix to write under, so each artifact needs its own URL, and the URLs have to be
minted per session. With only `WINDOWS_MCP_EXPORT_SIGNED_URL` set, the bundle
ships alone and the sidecars are reported as not shipped in the receipt — never
silently omitted.

The credentialed `s3`, `azblob` and `gcs` providers, addressed by bucket and
authenticated by a service principal, land with their SDK backends. Until then a
policy naming one is **refused at load**, not accepted and failed at session end:
a document that validates against a server that cannot do what it says is the
failure mode the whole schema-validation pass exists to prevent.

## Credentials

Secrets come from fixed environment variables. Never from flags — argv is
world-readable — and never from the policy document, which is registered as an
agent-readable protected path and is meant to be reviewable and checked in. The
document carries routing only, and a test asserts on its serialized keys to keep
it that way.

| Variable | Holds |
|---|---|
| `WINDOWS_MCP_EXPORT_SIGNED_URL` | The bundle's pre-signed PUT / SAS / signed URL |
| `WINDOWS_MCP_EXPORT_SIGNED_URL_MANIFEST` | The manifest sidecar's URL (optional) |
| `WINDOWS_MCP_EXPORT_SIGNED_URL_SIGNATURE` | The signature sidecar's URL (optional) |

**A signed URL is a write credential**, not an address: the signature travels in
the query string, so anyone holding the URL can write to that object. It is
treated as a secret throughout — cleared from the process environment at startup
by `scrubSecretEnv`, withheld from every child process, and redacted to scheme,
host and path before it can reach a log line, an error message or the receipt.

The `WINDOWS_MCP_EXPORT_` prefix is load-bearing rather than cosmetic. That prefix
is what `internal/desktop` strips when it builds a child environment, so a
credential named `AWS_SECRET_ACCESS_KEY` or `AZURE_CLIENT_SECRET` in the vendor's
own style would be readable by every PowerShell the agent runs. It is also why the
SDK backends will use explicit static credentials rather than their default
credential chains: those chains read exactly those bare names.

Two suffix conventions apply: `_KEY` / `_TOKEN` / `_SECRET` hold an inline value
and `_KEY_FILE` holds a path. `WINDOWS_MCP_EXPORT_SIGNED_URL` is a documented
exception — it is a secret whose only sensible shape is a URL.

## Evidence is never overwritten

Every upload is **create-only**. An object already at the key is somebody's record
of a session, and replacing it would destroy exactly the artifact this subsystem
exists to preserve — so the request carries `If-None-Match: *` and a destination
that already holds the object refuses the write.

That refusal is a **failure**, recorded in the receipt as such. It is not retried
past and not treated as success: if you see it, a session's evidence did not
leave the device, and the reason is that something was already there.

Two things worth knowing:

- The condition is enforced by the **store**, because for a signed URL it is the
  only place it can be. The object name is covered by the signature, so this end
  cannot pick a different key to avoid a collision. S3 answers `412` and Azure
  answers `409`; both are reported as a refused overwrite.
- **Google Cloud Storage is the exception.** Its XML API uses
  `x-goog-if-generation-match: 0` rather than `If-None-Match`, and that header
  would have to be covered by the V4 signature to take effect — so a GCS signed
  URL carries no server-side create-only guarantee from here. Mint GCS URLs
  per session, and prefer a bucket with object versioning or a retention policy.

Sending `If-None-Match` is safe on an already-signed URL: SigV4 enforces only the
headers named in `SignedHeaders`, and an Azure SAS signature covers the URL rather
than the request headers.

## The receipt

The upload happens **after** the audit chain is closed, and that is not an
oversight to engineer around: the bundle *contains* the chain, so the chain must
be sealed before the bundle can be, and resealing afterwards to fold in the
outcome would invalidate the manifest the bundle was signed over.

So the record is split. **The chain carries the intent; a file carries the
outcome.**

- `export.configured` is written to the audit chain at startup, naming the
  provider and the destination. `export.disabled` is written instead when a
  destination was configured and could not be built, with the reason.
- `<evidence_dir>/session-<stamp>.export.json` is written at session end:

```jsonc
{
  "version": 1,
  "session": "20260805-141122",
  "created_at": "2026-08-05T14:13:02Z",
  "provider": "signed_url",
  "destination": "https://acme.blob.core.windows.net/evidence/session-20260805-141122.evidence.zip",
  "audit_head": "9f2c…",
  "objects": [
    { "name": "session-20260805-141122.evidence.zip",  "bytes": 4182233, "sha256": "…", "uri": "…", "shipped": true },
    { "name": "session-20260805-141122.manifest.json", "bytes": 1841,    "sha256": "…", "uri": "…", "shipped": true },
    { "name": "session-20260805-141122.manifest.sig",  "shipped": false, "error": "upload failed: PUT … returned 403 Forbidden" }
  ]
}
```

A receipt with any `"shipped": false` is what a fleet collector looks for. It is
written **even when nothing shipped at all**, so *the device never tried* and *the
device tried and could not reach the destination* are distinguishable — silence is
the one answer an evidence trail must never give.

Each object's `sha256` is the digest of the bytes that were sent, and it is also
attached to the object's metadata at the destination, so a reviewer pulling the
bundle out of the bucket can tell it is the artifact this device sealed without
unpacking it.

## Where it runs, and what that constrains

The export fires from inside the audit-close defer, after the chain is sealed and
after the recorder is finalized — both are inputs to the bundle. Three
consequences follow, and each is a property rather than an accident:

- **It never fails the session.** A destination that cannot be built disables
  export with a warning; an upload that fails is logged and recorded. A missing
  upload must not turn a clean exit into a crash the host reads as instability.
  The whole path, seal included, is wrapped in a `recover()`.
- **It runs on a fresh, bounded context.** The session's context is already
  cancelled by then, so the upload gets its own budget — `transparency.export.timeout`,
  defaulting to two minutes. A hang here is indistinguishable to the host from a
  crash, so it gives up rather than wedging the exit.
- **It cannot use the device egress proxy.** The proxy is stopped by its own
  defer *before* this one. See below.

## Interaction with egress

The uploader has its own hardened dialer, the same one the
[Scrape tool](toolsets-and-personas.md) and the [egress proxy](egress.md) use: it
resolves the destination, refuses the answer if *any* address is loopback,
RFC1918, CGNAT, link-local or an IANA special-purpose range, and dials the vetted
address rather than re-resolving the name. `169.254.169.254` is refused with
everything else, which is the point — the cloud metadata endpoint is exactly what
a no-ambient-credentials rule is protecting.

It does **not** honour `HTTP_PROXY`: sending the bundle, and for a signed URL its
credential, to whatever a per-user environment variable named would route around
the vetting above.

When [egress](egress.md) is enabled the server warns at startup, because two
things need doing that it cannot do for you:

- **List the destination host in `egress.allow`.** For a `signed_url` destination
  the host lives in an environment variable, so the policy loader has no host to
  cross-check and cannot settle this at load.
- **Under `scoped` or `global` enforcement, give this server's own executable an
  outbound allow rule.** Otherwise `block_all_outbound` blocks the upload along
  with everything else, and the bundle never leaves.

## Limits worth knowing

- **A failed upload is not retried.** The receipt is the record; re-shipping is
  manual. There is no spool, and no `evidence export` CLI verb yet.
- **The outcome is not in the audit chain**, and cannot be. See
  [the receipt](#the-receipt).
- **Write-only credentials are the intended posture.** Nothing here reads back
  from the destination, and the principal should not be able to.
- **A local administrator can undo any of it.** They can clear the environment
  before the server starts, or delete the bundle before it is sealed. This is a
  guardrail, not a boundary — the same caveat that applies to
  [egress](policy-config.md#egress-the-domains-the-device-may-reach).

## Deliberately not covered

- **Ambient credential chains.** `config.LoadDefaultConfig`,
  `azidentity.DefaultAzureCredential` and Google ADC are not used and will not be
  added. They read the vendors' bare environment names, which are not withheld
  from child processes, and they reach IMDS, which the dialer refuses. Managed
  identity and instance roles are therefore not supported, by design.
- **Streaming or incremental upload during a session.** Evidence is shipped once,
  sealed, at the end. A partial bundle is not evidence.
- **Deleting the local copy after a successful upload.** The bundle stays where it
  was sealed. Retention is the operator's policy, not this server's.
