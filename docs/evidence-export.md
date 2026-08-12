# Evidence export — moved

The guardrails packages this document describes were extracted into the
[agentweave-harness](https://github.com/deploymenttheory/agentweave-harness)
module, and this document moved with them.

**See [`docs/evidence-export.md`](https://github.com/deploymenttheory/agentweave-harness/blob/main/docs/evidence-export.md) in the agentweave-harness repository.**

This server imports those packages for its standalone (in-process) stack, so
the behaviour they describe still applies here; the reference now lives with the
code. See also `docs/security-architecture.md` in this repo for the host-side
residue (credentials, probes, actuators, the STA thread, the stdio posture) that
did not move.
