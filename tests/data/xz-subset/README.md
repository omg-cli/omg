# XZ decoder behavior fixtures

OMG downloads runtime archives and inspects AUR packages that may use XZ. These
fixtures are produced by `generate.sh` with the system `xz` encoder. The runtime
tests pass them through `extract_component_tar_xz`, including its output budget
and tar extraction, rather than checking only a parser or header.

| fixture | blocks | check | required behavior |
|---|---:|---|---|
| `single-block-crc64.tar.xz` | 1 | CRC64 | extract three files |
| `single-block-none.tar.xz` | 1 | none | extract three files |
| `multi-block-crc64.tar.xz` | 13 | CRC64 | extract three files |
| `single-block-sha256.tar.xz` | 1 | SHA-256 | extract three files |
| `multi-block-sha256.tar.xz` | 13 | SHA-256 | extract three files |

The SHA-256 fixture also has a negative test: changing a byte in its block
check must fail before any tar entry is published. The decoder is drained into
a bounded temporary file before tar parsing, so a caller selecting only a few
entries still checks the entire XZ stream and footer. Its per-block decoder
memory is capped at 256 MiB. See the upstream
[`XzReader::new_mem_limit` API](https://docs.rs/lzma-rust2/0.21.0/lzma_rust2/struct.XzReader.html).

## Why the decoder changed

The former `lzma-rs` dependency describes its XZ support as a subset and
[records that SHA-256 checks are unsupported](https://github.com/gendx/lzma-rs/pull/40).
The maintained [lzma-rust2](https://github.com/hasenbanck/lzma-rust2)
implements the XZ SHA-256 check and a streaming reader. OMG disables its
optional `optimization` feature, leaving the safe-Rust implementation. In a
local Debian probe, both decoders accepted the complete, checksum-verified
[Node 24.21.0 archive](https://nodejs.org/dist/v24.21.0/); `lzma-rust2` also
accepted the SHA-256 fixture that `lzma-rs` rejected. The Node archive's
published SHA-256 was
`fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6`.
That result establishes support for these inputs; it does not explain the
intermittent CRC64 failure tracked in #621, which remains open for repeat QEMU
evidence.

Regenerate with `bash tests/data/xz-subset/generate.sh`. Review the generated
binary changes alongside the test result; the fixtures are input artifacts,
not pre-approved downloads.
