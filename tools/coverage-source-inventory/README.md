# Rust source inventory

This standalone maintenance crate supplies parsed Rust syntax facts to source-coverage analysis. It uses the same pinned `syn` and `proc-macro2` versions as OMG's source-audit tests and adds no dependency to the package-manager runtime.

Run its tests from the repository root:

```sh
cargo test --locked --manifest-path tools/coverage-source-inventory/Cargo.toml
```

The CLI reads one UTF-8 Rust file on stdin and writes one JSON inventory on stdout:

```sh
cargo run --locked --manifest-path tools/coverage-source-inventory/Cargo.toml < src/package_managers/alpm_ops.rs
```

Each node records its kind, nearest recorded parent, original byte and line/byte-column spans, and available name, attribute, parameter, body and expression-role spans. Macro token trees and attributes remain opaque. `acceptance` is always false: these facts do not resolve bindings, pair revisions, establish execution or authorize deletion credit.

Fixed limits are 1 MiB input, 50,000 nodes, 128 lexical/recorded ancestry levels, a 512-token cumulative path bound and 16 MiB JSON. The parser uses a bounded 16 MiB stack. Callers should also impose subprocess CPU, memory and wall-clock limits. A refused input exits nonzero without a partial JSON inventory.
