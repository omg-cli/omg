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
