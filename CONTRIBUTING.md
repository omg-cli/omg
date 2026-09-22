# Contributing to OMG

Start with a reproducible bug, a focused code change, or a documentation correction.
Describe the behavior you changed and the checks you ran.

OMG is in beta. Package operations can change the host, and some tests call native
package tools. Read [the test guide](tests/README.md) before running broad suites.

## Get a checkout

You need Git and the Rust toolchain pinned in [rust-toolchain.toml](rust-toolchain.toml)
(currently 1.95.0). The project uses Rust edition 2024. Build dependencies differ by
backend. Arch needs libalpm and build tools; Debian and Ubuntu need the APT
development library, Clang, CMake, pkg-config, and OpenSSL development headers.
Fedora uses RPM and DNF tooling; [Dockerfile.fedora](Dockerfile.fedora) lists the
tools used by its build check. macOS needs Xcode Command Line Tools. See
[installation](docs/installation.md#build-from-source) for the backend requirements.

```bash
git clone https://github.com/omg-cli/omg.git
cd omg
rustc --version
```

Select the backend for your host. Cargo features are additive, so use
`--no-default-features` when building a non-Arch backend.

| Host | Build command |
| --- | --- |
| Arch Linux | `cargo build --locked --no-default-features --features arch,pgp,license` |
| Debian or Ubuntu | `cargo build --locked --no-default-features --features debian,pgp,license` |
| Fedora | `cargo build --locked --no-default-features --features fedora,pgp,license` |
| Apple silicon macOS | `cargo build --locked --no-default-features --features macos,pgp,license` |

The release workflow uses these same backend feature sets. Debian 13 and Ubuntu
26.04 need the APT 7 release archive; Debian 12 and Ubuntu 24.04 use APT 6.
`debian-pure` is for indexing and fixtures, not live package mutations.

After building, try a read-only command with the same feature set. For example,
on Arch:

```bash
cargo run --locked --no-default-features --features arch,pgp,license --bin omg -- search ripgrep
```

Use a disposable container or virtual machine for backend integration work.

## Find the code

| Area | Starting point |
| --- | --- |
| Command names and options | [src/cli/args.rs](src/cli/args.rs) |
| CLI dispatch | [src/bin/omg.rs](src/bin/omg.rs) |
| Package backends | [src/package_managers/](src/package_managers/) |
| Runtime managers and tool registry | [src/runtimes/](src/runtimes/) |
| Optional daemon and local protocol | [src/daemon/](src/daemon/) |
| Configuration | [src/config/](src/config/) |
| Security checks | [src/core/security/](src/core/security/) and [src/cli/security.rs](src/cli/security.rs) |
| User documentation | [docs/index.md](docs/index.md) |

[Architecture](docs/architecture.md) explains the CLI, daemon, and backend
boundaries. [AGENTS.md](AGENTS.md) records the repository's working rules.

## Make a change

Keep changes focused and preserve security limitations. Never use `as any`,
`@ts-ignore`, empty catches, or deleted tests to hide a failure. Update the
relevant guide when you change a command, option, default, supported platform,
file format, or trust boundary. Follow [documentation style](docs/documentation-style.md)
and check examples against [the parser](src/cli/args.rs) and the implementation.

For Rust changes, run the narrowest useful check first. These commands check
formatting and a selected backend without changing packages:

```bash
cargo fmt --all -- --check
cargo check --locked --no-default-features --features arch,pgp,license
```

Change the feature set for your host. Do not use `--all-features` to combine
incompatible native package backends. For a broader local gate on a supported
Unix development host, `make ci-local-quick` runs shell syntax checks, Python
fixtures, formatting, portable compilation, and fuzz compilation. The full
gate adds feature-specific Clippy and nextest runs. It needs the tools named
in [Makefile](Makefile), including `cargo nextest` for the full gate.

```bash
make ci-local-quick
make ci-local-full
```

Some tests bypass the shared isolated CLI runner or call native package tools.
`OMG_TEST_MODE=1` is not a sandbox. Read [tests/README.md](tests/README.md)
before setting `OMG_RUN_SYSTEM_TESTS`, `OMG_RUN_NETWORK_TESTS`, or
`OMG_RUN_DESTRUCTIVE_TESTS`.

For documentation changes, run the repository's command, environment, link,
and configuration audits:

```bash
python3 scripts/check-docs-alignment.py .
python3 scripts/audit_docs.py
python3 scripts/test_docs_alignment.py
```

These scripts catch many stale references. They cannot prove that a prose
description matches runtime behavior, so inspect the code for each claim you edit.

## Open a pull request

Explain the user-visible change, the backend and feature set you checked,
and any limits of that verification. Include a test for a behavior change
when it can fail on a real regression. Keep generated benchmark claims tied
to their [recorded conditions](benchmarks/README.md).

Before requesting review:

1. Check the diff for unrelated changes and accidental secrets.
2. Run the relevant narrow checks, then the broader gate where feasible.
3. Update the affected docs and state any platform you could not test.

Use [GitHub Issues](https://github.com/omg-cli/omg/issues) for bugs and feature
requests. Include your OMG version, operating system, backend, exact command,
and redacted output. Report security concerns privately using
[SECURITY.md](SECURITY.md). Do not post a suspected vulnerability in a public issue.

Contributions are licensed under [MIT](LICENSE).
