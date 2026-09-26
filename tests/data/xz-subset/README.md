# XZ decoder capability fixtures

These archives pin what the pure-Rust XZ decoder can read, because OMG installs
XZ archives published by other projects. They are consumed by two tests in
`src/runtimes/common.rs`, both of which call the real extraction function:

- `supported_xz_stream_variants_decode_through_the_extraction_path`
- `sha256_checked_xz_streams_fail_with_the_identity_diagnostic`

## Why the split exists

lzma-rs describes itself as supporting "LZMA, LZMA2 and **a subset of the .xz file
format**" (<https://github.com/gendx/lzma-rs>), and its changelog records the gap
directly:

> 0.1.3 — "Return an error instead of panicking on unsupported SHA-256 checksum
> for XZ decoding" (<https://github.com/gendx/lzma-rs/pull/40>)

0.3.0 (published 2023-01-04) is still the newest release on crates.io
(`https://crates.io/api/v1/crates/lzma-rs` → `max_version: 0.3.0`), so SHA-256
checked streams are **not** readable by the version this project depends on
(`lzma-rs = "0.3"`). Nothing else about the container is a problem: multi-block
streams and CRC64 checks decode.

## What each fixture is

| fixture | blocks | check | expected result |
|---|---|---|---|
| `single-block-crc64.tar.xz` | 1 | CRC64 | decodes |
| `single-block-none.tar.xz` | 1 | none | decodes |
| `multi-block-crc64.tar.xz` | 13 | CRC64 | decodes |
| `single-block-sha256.tar.xz` | 1 | SHA-256 | rejected with the archive identity |
| `multi-block-sha256.tar.xz` | 13 | SHA-256 | rejected with the archive identity |

## Archives OMG installs today (checked 2026-09-26)

The XZ stream header is 12 bytes: 6 magic, 2 stream flags (byte 7 is the check
id: `0x00` none, `0x01` CRC32, `0x04` CRC64, `0x0A` SHA-256), 4 CRC32. Fetching
those bytes is enough to know whether a publisher's archive is decodable:

| archive | header | check | decodable |
|---|---|---|---|
| `node-v24.21.0-linux-x64.tar.xz` | `fd377a585a000004e6d6b446` | CRC64 | yes |
| `rust-1.95.0-x86_64-unknown-linux-gnu.tar.xz` | `fd377a585a000000ff12d941` | none | yes |

Python and Go archives are gzip, which has its own decoder. The SHA-256 gap is
therefore latent rather than active: it becomes an install failure the day a
publisher switches check type, and the tests above turn that into a named error
instead of a mystery.

## Regenerating

```bash
bash tests/data/xz-subset/generate.sh
```

The script rebuilds every fixture from one small tar with the system `xz`
(default CRC64, `--check=none`, `--check=sha256`, and `--block-size=4KiB` for the
multi-block variants) and prints each file's block count and check type.

Do not delete these fixtures: if lzma-rs ever implements SHA-256, the second test
fails on purpose so the supported-variant list and this page are updated
together.
