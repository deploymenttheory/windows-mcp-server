# Releasing the Windows server

The release workflow builds Windows amd64 and arm64 executables from one tag,
signs both with an Azure Artifact Signing **Public Trust** certificate, and
publishes verified ZIPs. The Claude Desktop `.mcpb` contains the same signed
amd64 executable. The bundle is limited to amd64 because MCPB 0.3 selects an
operating system but does not select a CPU architecture; arm64 users can install
the direct ZIP. The `.mcpb` itself has a keyless Sigstore signature as a separate
release asset, not an embedded MCPB signature.

## One-time Azure signing setup

An Azure tenant alone is insufficient. Create an Artifact Signing account,
complete the organization's [Public Trust identity
validation](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart),
and create a Public Trust certificate profile. A Public Trust Test profile is
for testing and must not sign public downloads. Give a dedicated Microsoft Entra
application the **Artifact Signing Certificate Profile Signer** role at the
certificate profile scope. The signing key stays with Microsoft.

Configure a federated credential on that application with issuer
`https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`,
and this GitHub environment subject:

```text
repo:deploymenttheory@103241062/windows-mcp-server@1310797963:environment:windows-release-signing
```

This repository uses GitHub's immutable OIDC subject format. If it is moved or
renamed, check the current `sub_claim_prefix` with
`gh api repos/deploymenttheory/windows-mcp-server/actions/oidc/customization/sub`
and update the federated credential. Create the GitHub environment
`windows-release-signing` and restrict deployment branches/tags to `main` and
release tags (`v*`). This keeps manual recovery and tag pushes on one Azure
federated credential.

Set these GitHub **environment secrets**:

| Secret | Value |
| --- | --- |
| `AZURE_CLIENT_ID` | Entra application's client ID |
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription containing Artifact Signing |

Set these GitHub **environment variables**:

| Variable | Value |
| --- | --- |
| `AZURE_SIGNING_ENDPOINT` | Account region endpoint, such as `https://eus.codesigning.azure.net/` |
| `AZURE_SIGNING_ACCOUNT` | Artifact Signing account name |
| `AZURE_SIGNING_PROFILE` | Public Trust certificate profile name |

The workflow fails before publication if a setting is missing or an executable
does not have a valid Authenticode signature. No client secret or PFX is needed.
See the [Azure GitHub action](https://github.com/Azure/artifact-signing-action)
and its [OIDC setup](https://github.com/Azure/artifact-signing-action/blob/main/docs/OIDC.md)
for the Microsoft side of this configuration.

## Version and publication policy

Release Please owns the version, changelog, tag and draft GitHub release. The
manifest starts at the already public v1.4.0; no existing tag is changed.
Merging a Release Please PR creates a draft and the tag that starts
`release.yml`. The new distribution path publishes **preview** releases until
it has clean-device client and upgrade evidence. The preview flag is set in
`release.yml`; changing the semantic version alone does not remove it.

The binary `--version`, archive names, MCPB manifest and MCP Registry entry
must all name the same version. The Registry entry must record the exact
released MCPB SHA-256. Keep published tags and assets immutable; fix a public
defect in a new patch release.

## Release flow

1. Merge code only after the build, packaging and MCP spec gates pass. Review
   and merge the Release Please PR. It creates a draft GitHub release and tag.
2. The Windows runner builds both architectures from that tag. Azure Artifact
   Signing adds timestamped Authenticode signatures to the executables. Only
   then does the workflow make the ZIPs and amd64 `.mcpb`. It checks the
   package bytes, executable signatures, version, SHA-256 files, keyless
   Sigstore signatures and CycloneDX SBOMs. Any failure leaves the draft
   unpublished.
3. The workflow publishes the verified release as a preview, then registers
   its `.mcpb` with the [MCP Registry](https://registry.modelcontextprotocol.io)
   using GitHub OIDC. A Registry outage does not change the already public
   assets; `publish-mcp-registry` can retry the same tag after verifying its
   checksum.
4. On a clean interactive Windows machine, install the released amd64 ZIP,
   connect Codex and Claude Code, and execute a desktop tool. Install the
   `.mcpb` in Claude Desktop and repeat. Test the arm64 ZIP on Windows on ARM.
   Repeat after an upgrade, confirming that client paths, Authenticode trust,
   policy files and desktop access still work. Hosted runners cannot perform
   those interactive checks. The existing [disposable guest acceptance
   suite](acceptance-testing.md) covers the engine and guardrails separately.
5. After the Desktop bundle works, submit that exact release file to
   [Anthropic's extension directory](https://support.claude.com/en/articles/10949351-getting-started-with-local-mcp-servers-on-claude-desktop).
   The GitHub asset remains the direct download during directory review.

## Recovery

Run `release.yml` manually from `main` with the existing **draft** tag when a
workflow bug needs repair. The source and GoReleaser configuration come from
the tag; packaging helpers and MCPB manifest come from the exact workflow
commit and are staged outside the checkout. A public release cannot be
rebuilt. If the Registry alone failed, rerun only `publish-mcp-registry` for
the public tag. If a public package is defective, publish a new version.

The current distribution channels are GitHub ZIPs, a GitHub `.mcpb`, and the
MCP Registry listing. A Windows package-manager channel requires a separate
installer or portable-package submission and is not claimed by this workflow.
