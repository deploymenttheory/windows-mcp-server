# Policy configuration — moved

The policy engine and its document schema were extracted into the
[agentweave-harness](https://github.com/deploymenttheory/agentweave-harness)
module. The reference now lives with the code:

- **Base document schema** (signals, rules, rate limits, egress, transparency,
  approvals, kill, in-flight, enforce_https):
  [`docs/policy-config.md`](https://github.com/deploymenttheory/agentweave-harness/blob/main/docs/policy-config.md)
- **Layered composition + session manifests + argument constraints** (what the
  harness adds when it governs a session):
  [`docs/policy-layering.md`](https://github.com/deploymenttheory/agentweave-harness/blob/main/docs/policy-layering.md)

This server imports the policy package for its standalone (in-process) stack, so
the base schema applies to `--policy-config` here exactly as documented there.
The layered features activate only under `agentweave-harness run`.
