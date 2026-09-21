# Go installation behavior

The runtime inventory lacks a real Go installation row. Add a pinned supported release with an isolated install, internal active link/compiler/GOROOT checks, then compile, execute and test a small standard-library-only module. Require known-value hashing, compression/JSON roundtrips and a goroutine/channel result. A successful version command or no-op compiler is insufficient. Verify cleanup and preserve stage-specific failure diagnostics.

The official https://go.dev/dl/?mode=json endpoint observed on 2026-09-21 lists go1.27.1 as stable. Pin that release for reproducibility; do not silently use whichever host compiler is available.

Research through Exa: https://go.dev/doc/toolchain documents automatic toolchain selection and that GOTOOLCHAIN=local always runs the bundled toolchain. The oracle must set this explicitly, disable user GOENV/workspace settings and module proxy access, use a private cache/workspace, and avoid external dependencies. Upstream tests at https://go.dev/src/cmd/go/testdata/script/gotoolchain_local.txt also distinguish local selection from automatic downloads.

Implementation sequence: prove a real local fixture on four WSL distros; add a runner regression rejecting an installer that reports success without a usable toolchain; implement the exact compiler/program/test assertions and adversarial cases; register the new inventory identity and network requirement; validate policy and runner suites; collect fresh hosted QEMU evidence. Keep historical inventory identities. No source-code coverage or exhaustive Go library coverage is inferred.

CGO is deliberately disabled for this standard-library fixture. C toolchain interoperability, cross compilation, module downloads, all Go runtime flags and runtime uninstall/partial-version behavior remain separate obligations.

## Local feasibility

The real OMG debug binaries installed Go1.27.1 as an unprivileged user on all four WSL distros. Each isolated runtime compiled and ran the standard-library fixture with exact output `OMG_GO_RUNTIME_OK:go1.27.1`; `go test -count=1` executed and passed `TestProbe`. These were incremental local binaries; this is not admitted current-revision hosted evidence. Fixtures remain for exact-oracle validation:

- Ubuntu `/home/omg-audit/omg-go-behavior.HYBkAe`
- Arch `/home/omg-audit/omg-go-behavior.fNSWQg`
- Debian `/home/omg-audit/omg-go-behavior.GDXZzv`
- Fedora `/home/omg-audit/omg-go-behavior.eHbNbt`

The QEMU runner now includes the row and exact oracle. The initial regression accepted an installer message with no compiler, then correctly rejected it after implementation. Additional fixtures reject inactive/escaped compilers, version-only tools, no-op builds, wrong compiled output, no-op tests and explicit failing tests while preserving diagnostics. Successful fake fixtures test admission only.

The exact extracted oracle passed against all four real WSL installations above. On Ubuntu, temporarily removing the installed `pkg/tool/linux_amd64/compile` caused a compilation-stage failure; restoring the same file recovered a pass. Temporary behavior fixtures are removed and their absence checked. The output/policy/network suite passed all37 tests. The new Go identity replaces only the Node-only policy identity on the unpushed local branch; published and hosted historical identities are unchanged. Hosted QEMU validation remains pending, and these results do not close the global behavioral coverage gap.
