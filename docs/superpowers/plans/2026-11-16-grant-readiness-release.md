# Grant readiness and release batch

Implemented: FUNDING.yml points to the verified public `PyRo1121` Sponsors listing; Contributor Covenant 2.0 and maintainer-led governance are included; existing SECURITY.md is retained. The pinned Scorecard workflow runs on main pushes and weekly, publishes SARIF with job-scoped permissions, and uses only upstream-approved actions. The release workflow now attaches its existing GitHub/Sigstore provenance bundle as `omg-release.sigstore.json`; notes explain verification with the exact repository, tag and workflow identity. Six release-collection tests, 17 workflow-boundary tests and 21 CI-gate tests pass locally. Actual Scorecard publication requires merging to main, and signing is operational evidence only after a real published release is verified. No grant application has been submitted.

The user explicitly requested committing, pushing and merging the combined security/release work, plus GitHub Sponsors, community/governance files, OpenSSF Scorecard and release signing. This extends the active CVE release requirement; it does not replace native coverage, runtime/package admission or release acceptance.

## Verified account and existing controls

GitHub GraphQL confirms `omg-cli/omg` is public, has no funding links, and the authenticated maintainer `PyRo1121` can administer the organization. `omg-cli` has no Sponsors listing. `PyRo1121` already has a public active Sponsors listing, so use that existing receiving account in FUNDING.yml rather than creating a financial onboarding dependency. CODEOWNERS names the same maintainer. No payout information or new account credential is needed for that link.

Root SECURITY.md and the MIT license already exist. Preserve the security reporting channel and existing policy; no new exclusions, accepted risks or severity changes are authorized by a funding-readiness request. Add the missing code of conduct and short maintainer-led governance document. Do not claim nonprofit or tax-deductible status, fiscal-host membership, grant acceptance or a second administrator.

The release workflow already uses pinned GitHub build-provenance attestations for all release archives and the Cargo SBOM. Inspect the actual publication and verification paths before extending signing. Preserve exact-commit CI gates and artifact verification; v0.1.225 must include finished CVE admission and truthful release notes.

## Coherent batch

1. Complete and verify package/runtime CVE admission, publisher authentication, feed/cache operations and the user's real WSL installation controls under the existing release plan.
2. Add FUNDING.yml using the verified active receiving account, a standard attributed code of conduct, and GOVERNANCE.md. Keep existing SECURITY.md unless a separately justified correction is required.
3. Add a SHA-pinned, minimal-permission OpenSSF Scorecard workflow using the supported default token and actual public-result/SARIF requirements. Verify a real run and report its actual results; do not invent a score or certification.
4. Publish verifiable release signature/attestation material for v0.1.225 through the existing protected release workflow, then verify the published assets and identity. A configured signing step is not a signed release.
5. Commit and push the coherent verified patch to the existing PR branch, finish independent review and actual terminal checks, fix failures without weakening gates, merge the verified head and publish the release. No new worktree or branch is needed.

## Application readiness

Prepare an evidence-based application checklist after verifying current official criteria. Neon describes platform credits and potential cash sponsorship through GitHub Sponsors. Vercel currently says applications are closed and requires Vercel hosting or intended hosting as well as a code of conduct. Open Source Collective requires an organizational repository and encourages shared administration/governance; the existing org meets only that particular repository condition. Netlify and other programs need their own current eligibility checks. These files alone do not establish acceptance or open an application window.

Sources checked 2026-11-16:

- https://neon.com/blog/neon-open-source-program
- https://vercel.com/open-source-program
- https://docs.oscollective.org/interested-in-joining-osc/acceptance-criteria
- https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/displaying-a-sponsor-button-in-your-repository
- https://github.com/ossf/scorecard-action/blob/main/README.md
