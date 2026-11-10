# Local Windows WHPX versus GitHub release builds

On November 10, 2026, the local i9-14900K completed this cold Ubuntu release build in **337.02 seconds**, compared with **520.53 seconds** on a GitHub public runner. Local elapsed time was **35.25% lower** for this sample. The first library-test compile and run took **342.54 seconds locally** and **416.34 seconds on GitHub**, or **17.73% less time locally**.

These results support local development for this workload. They do not establish a speed advantage over an untested VPS or compare the full parallel GitHub CI matrix.

## Measurements

| Phase | Local | GitHub |
| --- | ---: | ---: |
| Cold release build of `omg` and `omgd` | 337.02s | 520.53s |
| Unchanged warm build, median of three | 0.352s | 0.402s |
| First selected test, including first release libtest compilation | 342.54s | 416.34s |
| Same selected test warm, median of three | 0.503s | 0.402s |
| Second selected test first invocation, reusing compiled libtest | 0.805s | 0.402s |
| Second selected test warm, median of three | 0.553s | 0.402s |

Each environment completed 17 measured commands, including eight exact named-test executions. Both binaries passed version and help checks. The read-only `omg --json explicit` result matched the complete native explicit package set, and installed package state remained unchanged. Every phase's stdout and stderr SHA-256 was checked against its receipt.

## Matched inputs

- Application revision: `329ed5b7a2d01ce40cbe0b0b70f42d66cfebd0ee`.
- Measurement driver revision: `12a972cfd20560f97d29189ca2e0cc817f9174a4`.
- Shared script SHA-256: `8547944aa09b09acf467abc4c3f4763bc221df89043e4c412e2771ed6161c11b`.
- Source manifest SHA-256: `9128626db9e27d9376d60397baf66f7fdee3549c0efb8f15ceccdc81380c980b`.
- Rust 1.95.0, with matching complete compiler identity.
- GCC 13.3.0, Ubuntu package `13.3.0-6ubuntu2~24.04.1` on both machines.
- Ubuntu 24.04 x86_64, four Cargo jobs and features `debian,pgp,license`.
- Unmodified release profile: fat LTO, one codegen unit, optimization level 3, unwind and no incremental compilation.

The Git source archive hash, complete source manifest, measurement script, Cargo configuration, release settings and measured Cargo commands matched. The tested source tree was unchanged after each wave. The compiler cache was disabled, and no compiled target existed before the cold build. Dependency sources were prefetched outside timing.

## Environment and limits

The local run used four virtual CPUs and 8 GiB RAM in a disposable native Windows QEMU/WHPX guest on an i9-14900K host with 32 GiB installed RAM. The GitHub run exposed four CPUs on an AMD EPYC 7763 and approximately 16 GiB RAM. Installed package inventories and kernels differed. This compares these practical environments, not isolated processor performance or all available local cores.

Windows desktop activity remained present. Available host physical memory reached 339.54 MiB, while QEMU's peak working set was 6.22 GiB. The run completed without hitting its sustained-pressure stop condition. The guest shut down, its 1,698,234,368-byte allocated child disk was retired, and the prepared template and publisher image remained unchanged. No WSL distro or extra checkout was used.

Cold means compiled-target-cold, not a cold filesystem cache or uncached downloads. There was one cold sample per phase, so no cold variance estimate is available. Warm means unchanged source and retained targets within one guest. It measures artifact reuse, not recompilation after an edit. The Windows runner removes those targets when it retires the guest; separate invocations start cold again. Subsecond differences also include the runner's 50 ms polling interval.

The first selected test includes initial libtest compilation after the binary builds. The second selected test reuses that executable. Report these phases separately. Maximum process RSS from `wait4` is not the sum of simultaneous compiler memory. No release, coverage or security settings were reduced for the measurement.

## Evidence and reproduction

- [Completed GitHub run](https://github.com/omg-cli/omg/actions/runs/42851732274).
- [Compact machine-readable receipt](local-vs-github-2026-11-10.json), including individual warm samples, binary hashes, test names and resource limits.
- [Reproduction commands](../local-build-comparison.md).

The hosted raw artifact is `rust-comparison-42851732274-1`, artifact ID 13780849275. GitHub reports ZIP SHA-256 `7fb1cc1324bf2c47376c50f5e8531648059f2f7a65e77bc5e6407b7c83ac4fc3` and expiration on November 24, 2026. Local raw logs and host receipts are retained privately under this checkout's `.git/local-vs-github-20261110` and `.git/native-whpx-20261110` directories. This report does not promise permanent hosted raw-log availability.
