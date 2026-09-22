# Security Policy

## Supported Versions

We provide security updates for the following versions of OMG:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

Report suspected vulnerabilities privately so maintainers can investigate before details become public.

### How to Report

**Do NOT open a public issue for security vulnerabilities.**

Instead, please email: **<olen@latham.cloud>**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### What to Expect

The following are response targets, not a support SLA:

- **Initial Response:** Within 48 hours
- **Status Update:** Within 7 days
- **Fix Timeline:** Depends on severity
  - Critical: 1-3 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Next release cycle

### Disclosure Policy

- We follow responsible disclosure
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will notify you when the fix is released
- Public disclosure happens after the fix is available

## Security Features

OMG includes built-in security features:

### Package Security

- **Package verification:** Follows the selected backend and its repository trust settings; native PGP checks require the `pgp` feature
- **Vulnerability scanning:** Reports matched advisories for installed packages; no findings do not prove a package is safe
- **SBOM generation:** CycloneDX 1.5 installed-package inventory on Arch in v0.1.223; current main also supports Debian, Ubuntu, and Fedora when inventory and advisory data are available
- **Security Grading:** Source-based policy grades, not proof of package safety or SLSA levels
- **Audit Logging:** Local hash-chain consistency checks, not authenticated or complete history

### System Security

Automatic shell hooks select installed runtimes but do not import project
environment assignments or scripts. Use explicit `omg run` or tasks when
project environment behavior is intended. Pin/config reads are bounded and
reject symlinks and special files.

AUR builds use private per-invocation output, source and compiler-cache
directories. Legacy persistent build artifacts are not reused because source
hash markers do not authenticate archive payloads. Install-hook review must
render the complete accepted hook before authorization.

- **Privilege Separation:** Minimal sudo usage with sudoloop
- **Sandbox Support:** AUR builds can use bubblewrap/chroot
- **Secret Scanning:** `omg audit secrets` reports potential credentials when you run it; a clean result is not proof none remain
- **Policy Enforcement:** Configurable security policies via `policy.toml`

### Supply Chain Security

- **Dependency Pinning:** Lockfiles for reproducible builds
- **Release Attestations:** GitHub Actions provenance for release archives and the Cargo dependency SBOM; no claimed SLSA build level
- **Signature Verification:** Official package checks follow the selected backend's repository trust configuration
- **Runtime Integrity:** Publisher-provided checksums detect corruption where available; they do not authenticate a compromised publisher

The system SBOM includes a vulnerability scan and fails when its inventory or advisory
source fails. In v0.1.223, Debian and Ubuntu fail at that required scan and Fedora has no
system SBOM backend. The release SBOM is a separate inventory of Cargo dependencies. Neither
contains a resolved dependency graph for all software on the machine. macOS has no
system SBOM backend in this build.

## Known Security Considerations

### Third-Party Dependencies

OMG relies on several third-party crates. We regularly audit dependencies for security issues using `cargo audit`.

**Current Known Issues:**

No known dependency vulnerabilities are accepted. Release gates run `cargo audit`; yanked transitive packages are tracked separately from security advisories.

### Key Trust on First Use

AUR package keys listed in `validpgpkeys` are fetched over HKPS in builds with the `pgp` feature and imported into the user's GnuPG home on first sight, with no fingerprint confirmation prompt. The import prints the key fingerprint to stderr, and the GnuPG home is created `0700` (pre-existing homes are re-validated for ownership and mode before import). This is trust on first use, not independent publisher authentication. OMG also creates a package-scoped keyring containing the declared keys for the build.

Native Windows is not supported. Windows users should run OMG inside WSL, where the installed Linux distribution determines the package backend.

### Privilege Escalation

OMG requires sudo access for:

- Installing/removing system packages
- Modifying system files
- Installing AUR build outputs and preparing privileged build environments. Package build scripts run unprivileged.

**Mitigation:**

- Sudoloop limits password prompts
- Dry-run mode (`--dry-run`) shows what would happen
- Policy enforcement rejects operations covered by the active local policy; backend enforcement limits still apply
- Privileged OMG backends persist attempt and outcome records. Interrupted operations and external tools require separate investigation.

### AUR Package Security

AUR packages are community-maintained and not officially verified.

**Built-in Protections:**

- Security grading (COMMUNITY level)
- PKGBUILD review before build is enabled by default; disabling it is an explicit trust decision
- Sandboxed builds (bubblewrap/chroot)
- PGP verification where available

**Best Practices:**

- Review PKGBUILDs before installation
- Use `--dry-run` to preview changes
- Keep the default `review_pkgbuild = true` setting under `[aur]` in `~/.config/omg/config.toml`
- Check package popularity and votes

## Security Best Practices

### For Users

1. **Keep OMG Updated:**

   ```bash
   omg self-update
   ```

2. **Enable Security Features:**

   ```toml
   # ~/.config/omg/policy.toml
   minimum_grade = "Verified"  # Require the official-source policy grade
   require_pgp = true
   allow_aur = false  # Disable AUR if not needed
   ```

3. **Review Audit Logs:**

   ```bash
   omg audit log
   omg audit verify  # Check local hash-chain consistency
   ```

4. **Scan for Vulnerabilities:**

   ```bash
   omg audit scan
   omg audit fix --dry-run  # Preview available updates on Arch
   ```

### For Developers

1. **Run Security Audits:**

   ```bash
   cargo audit
   cargo clippy -- -D warnings
   ```

2. **Review Dependencies:**

   ```bash
   cargo tree
   cargo machete  # Find unused dependencies
   ```

3. **Test Security Features:**

   ```bash
   cargo test --features arch security
   ```

4. **Follow Secure Coding Practices:**
   - Avoid `unsafe` blocks unless absolutely necessary
   - Use `#[must_use]` on query functions
   - Add context to all errors
   - Validate all user input

## Security Updates

Security updates are announced via:

- GitHub Security Advisories
- [Release notes](docs/changelog.md)

## Compliance

OMG provides inventory and audit inputs, not compliance certification. It does not implement HIPAA controls.

`omg audit export --framework soc2` generates evidence on supported backends when their installed inventory and advisory sources are available. In published v0.1.223, this requires `omgd` and succeeds with the system SBOM on Arch; Debian and Ubuntu fail at the required SBOM scan, and Fedora lacks that backend. Current main supports Arch, Debian, Ubuntu, and Fedora and can scan directly when the daemon is unavailable. Other framework names on that command return unimplemented errors. `omg enterprise audit-export` remains Arch-only and generates the same generic inventory bundle for every accepted framework name; selecting HIPAA does not add HIPAA evidence. Period labels do not filter audit history.

Exports are plaintext JSON or CSV. Some use owner-only permissions, but that is not encryption. Restrict destinations, inspect contents and permissions, and encrypt externally when required. SBOMs do not include a resolved dependency graph. See [security evidence limits](docs/security.md) and [enterprise exports](docs/enterprise.md).

## Release Incident Response

If a published release is (or may be) compromised, follow this runbook.

### Signals

- `sync-r2` round-trip verification failure (byte-identical re-download check)
- A gitleaks / TruffleHog alert on any commit
- Client reports of checksum or attestation verification failures
- Unexpected commits to `.github/workflows/` on `main`

### Immediate containment (first hour)

1. **Stop exposure:** remove the affected archives, `.sha256` sidecars, and the SBOM from the GitHub Release, and delete the corresponding `omg-releases/` objects in R2. If a good earlier version exists, run `./scripts/r2-rollback.sh <previous-version>` so update checks resolve to it. The rollback requires all platform archives and sidecars, including the Trixie/APT7 pair. For a historical release predating APT7 artifacts, explicitly pass `--allow-legacy-apt6`; APT7-only clients will be unable to install that version. Use `--dry-run` to check availability before moving the marker. Never substitute an APT6 archive for the missing APT7 binary.
2. **Revoke tokens:** delete `CLOUDFLARE_API_TOKEN` immediately — do not wait for analysis. Rotate per the procedure in [docs/release-operations.md](docs/release-operations.md).
3. **Freeze releases:** no new tags until containment is confirmed.

### Assessment

4. Determine blast radius: compare attestation provenance (`gh attestation verify … -R omg-cli/omg`) and checksums for every published archive against the CI-generated artifacts (upload artifacts in the release run, plus `attest-build-provenance` records).
5. If CI itself is suspect, review workflow diffs, runner logs, and the vendored npm lockfile integrity (`.github/deps/release-tools/package-lock.json` has registered integrity hashes for every transitive dependency).

### Recovery

6. Fix the root cause on `main` and let CI go green.
7. Publish a new version tag and let the full pipeline rebuild, attest, verify, and publish. Do not move an existing published tag.
8. Publish a security advisory (and a changelog entry) describing the incident, affected versions, and remediation.
9. File a post-mortem; add regression tests where the failure slipped through.

Full release procedures and credential rotation: see [docs/release-operations.md](docs/release-operations.md).

## Contact

Security Team: **<olen@latham.cloud>**
General Support: **GitHub Issues**

## Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities. Credits will be listed here upon disclosure.

---

Current implementation details are documented in [the security reference](docs/security.md).

## Security boundaries and retained trust

Release installation requires GitHub CLI (`gh`) verification of the archive's
attestation against the requested tag and `.github/workflows/release.yml` in
`omg-cli/omg` (with legacy releases `<= v0.1.221` signed under `PyRo1121/omg`). A missing verifier or rejected attestation stops the installer.
Source builds require explicitly running a checked-out `install.sh --from-source`;
piped execution never builds the current directory. The initial bootstrap script
is executable code: fetching it from mutable `main` trusts the repository owner
and delivery channel before any archive verification runs. For reproducibility,
review a checkout at a commit you trust and run that copy of the script. Archive
attestation does not retroactively authenticate the bootstrap script.

Runtime downloads trust their documented upstream publishers. A digest delivered
by that publisher detects corruption but cannot protect against compromise of the
publisher and its metadata together. OMG does not claim independent provenance
for every runtime. The SLSA-named artifact command requires an exact certificate
identity and verifies supported Rekor artifact signatures, not in-toto build
provenance. Even successful checks return SLSA level `None`. A valid signature
from an arbitrary signer is insufficient.

AUR review covers the complete local regular-file source manifest, including
`.SRCINFO`, patches and install hooks. Source symlinks are rejected; replace them
with reviewed regular files. All cached, fresh, dependency and rollback archives
must match the reviewed output identity and exact install-hook bytes. Package
archives are snapshotted into sealed Linux files before approval and copied into
private root staging for the complete privileged transaction.

Bubblewrap builds are offline by default. The host prefetcher accepts only public
HTTPS destinations, checks every redirect and pins resolved addresses. Sources
that require build-time networking (including unsupported VCS prefetches) require
an explicit `[aur] allow_network = true` setting. That setting exposes local and
private services to the build; it is a trust decision. Chroot devtools cannot
promise this offline boundary and require the same explicit setting. Native
builds remain an explicit unsafe option and execute with `no_new_privs` so they
cannot gain root through a cached sudo ticket.

Explicit package policies are enforced again against ALPM's prepared install or
upgrade plan, including dependencies. Native APT/DNF/Homebrew install and upgrade paths
refuse explicit policies because OMG cannot guarantee their final plan matches a
separate precheck. Use their default policy or an enforceable ALPM transaction.
A build with only the `debian-pure` indexing feature refuses live Debian package
mutations because its user cache is not installation authority. The native APT
backend remains available for those operations.

Local audit verification establishes internal hash-chain consistency only. The
owner can rewrite and rehash a user-owned collection, remove entries, or delete
its incompleteness marker; successful verification is not proof of authenticity
or completeness. Operations executed inside privileged OMG backends additionally persist attempt
and outcome records synchronously under root-controlled `/var/lib/omg/audit`.
Trusted legacy `/var/log/omg` storage is migrated atomically without discarding history. Direct
external native launches record their attempt/outcome in the invoking user’s
collection. An
abruptly terminated operation may have an attempt without a completion record.
Daemon queue overflow or persistence failure leaves a durable `audit/incomplete`
marker and verification refuses to describe that collection as complete. Root
can still alter system logs. Independently retained or remotely collected logs
are required for evidence against the machine's administrator.

Dashboard account linking accepts `omg account link --token-stdin` or
`OMG_DASHBOARD_TOKEN`, avoiding a token in process arguments. Prefer stdin from
a secret manager; environment variables remain visible to sufficiently privileged
processes and should not be entered literally in shell history.
