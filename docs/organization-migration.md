---
title: Moving to omg-cli/omg
sidebar_position: 46
description: Verify updates across OMG's repository signing change
---

# Moving to omg-cli/omg

**In plain words:** This page is for anyone following an old link or an old instruction that points at a previous location of the project.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

OMG moved from `PyRo1121/omg` to `omg-cli/omg`. Download links redirect, but
cryptographic signer identities do not. Releases through v0.1.221 were signed
by the old repository; subsequent releases must verify against the organization.
The updater, installer and release tests choose exactly one identity by version.
A failed verification never retries against the other identity.

The original v0.1.221 Sigstore bundle was recovered through GitHub's user-scoped
attestation API and associated with the transferred repository. All five archive
checksums and the original signature were verified against release commit
`b058c1ab5d4fe7f4bff3532dda6e44f2fe5b7e7c`. This preserves the original release
evidence; it does not rebuild, replace or re-sign the published binaries.

## Existing installations

`omg self-update` upgrades OMG in place and retains checksum and provenance
verification. Routine upgrades do not require reinstalling configuration or
shell integration. Successful interactive commands can show a daily cached
notice directing users to this command; see [update notices](update-notices.md).

Binaries through v0.1.221 pin the old signing repository in their compiled code.
They cannot automatically trust the organization's future signatures. Moving
across that boundary requires a one-time verified in-place upgrade using the
organization-aware installer or the distribution's package manager. Inspect the
canonical installer from `https://getomg.xyz/install.sh` before running it; it must
contain the organization-aware signer selection before using it for this step.
After that upgrade, use `omg self-update` normally. Do not disable provenance
verification to work around the repository transfer.

If you do not know which version is installed, run `omg --version` first. For a
version through v0.1.221, follow the one-time verified upgrade path above.
For a later version, `omg self-update` uses the organization signing identity.
If verification fails, keep the error and the existing binary. Do not treat a
redirected download link as proof that its signer is trusted.

## Release checklist

- Merge and validate the organization-aware updater, installer and release tests.
- Synchronize the canonical installer into OMG-Web and deploy it before promotion.
- Build a new version under `omg-cli/omg`; retain immutable existing tags/assets.
- Verify all archives against that version's single expected signing identity.
- Exercise the legacy in-place migration and subsequent built-in update path.
- Document the one-time signer migration in the release notes before promotion.

## Where to go next

See [installation](./installation.md) for release verification and
[troubleshooting](./troubleshooting.md) for help with a failed update.
