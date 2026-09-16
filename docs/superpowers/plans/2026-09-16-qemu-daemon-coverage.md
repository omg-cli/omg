# All-Linux QEMU daemon coverage

**Goal:** Every selected Linux guest must exercise the real daemon from its tested archive.
**Cause:** Non-Arch staged/release archives omitted omgd even though all backend builds compile it; the daemon foreground inventory row was declaration-only. A successful daemon-status exit alone does not prove IPC health.
**Architecture:** Ship omg and omgd together in all Linux archives. Run an unprivileged, bounded lifecycle probe before benchmarks in the existing mandatory guest lifecycle. Keep it outside the generic CLI inventory because it owns a process, signal handling and restart state. The generic declaration row is not the source of lifecycle assurance.

- [x] Include omgd in x64 Arch/Debian/Ubuntu/Fedora and dispatched ARM Debian/Ubuntu/Fedora staged archives, and all published Linux archives.
- [x] Require matching daemon version and executable before package lifecycle tests.
- [x] Probe direct omgd startup and omg daemon --foreground, real Ping/Metrics IPC, private owned socket, duplicate-daemon rejection without socket replacement, already-running launcher behavior, graceful SIGTERM/socket cleanup and restart.
- [x] Capture bounded daemon logs and require a complete structured receipt on the controller; absent evidence fails even when the guest exits zero.
- [x] Add executable receipt-gate regressions and all-Linux packaging guards, run Bash syntax/actionlint.
- [ ] Run real hosted QEMU guests and inspect receipts for every selected distro.

Existing published versions missing omgd will now fail the stricter nightly lifecycle check rather than silently pass. Release new signed archives to resolve that historical packaging gap; never modify existing release artifacts in place or weaken the check for old versions. macOS packaging is outside this Linux QEMU change.

## Follow-up daemon review

- [x] Fix simulated guest evidence in release-smoke fixtures and assert missing/invalid daemon receipts remain harness failures. Hosted preparation passed on 667f17f6.
- [x] Remove the shell hook's global process-name gate. Another user's `omgd` must not suppress this user's socket/IPC check. The launcher already performs that check and enforces singleton ownership. Executable Bash regression covers a successful unrelated process lookup.
- [ ] Self-update currently extracts/replaces only `omg`, leaving the installed `omgd` at its old version. Implement paired extraction, bounded archive validation, staging and failure recovery before declaring daemon upgrades supported. Do not just overwrite one binary then the other without recovery tests.
- [ ] Check service-managed upgrades and restart behavior, including an already running old daemon.

Research: [pgrep manual](https://man7.org/linux/man-pages/man1/pgrep.1.html) confirms that name matching alone is not scoped to an effective user. Socket ping is stronger than adding a user filter because a matching process can still be unresponsive.
