# Investigate OMG performance

**In plain words:** Small changes that make repeated commands faster, and how to measure the difference honestly.

> New to the terminal? Read [Getting started](./getting-started.md) and keep
> [the glossary](./glossary.md) open while you work.

Measure the operation you need before changing configuration. A warm official-repository query is not equivalent to an AUR search over the network or a package installation.

## Start with recorded evidence

[Benchmark methodology](../benchmarks/README.md) defines the available measurements and links raw records. Record the OMG version, backend, query, cache state, enabled sources, and artifact hash when comparing runs. Verify that compared commands return equivalent results before publishing a speedup.

Smoke tests establish whether selected operations passed for a particular artifact and image. Their durations include setup and assertions; they are not per-command latency measurements.

## Compare daemon and direct queries

```bash
omg daemon-status
omg search ripgrep --no-aur
```

On Arch, `--no-aur` excludes the network-backed AUR search. Without it, OMG queries official repositories and AUR concurrently. Keep the query and sources unchanged across measurements.

The optional daemon keeps package indexes in memory. Start `omg daemon --foreground` in a separate terminal and repeat the same query. Separate cold startup from warm queries. Do not assume a fixed latency, speedup, or memory footprint.

Use the optional [user service](./configuration.md) only after creating its unit. Service enablement instructions do not install a missing unit.

## Tune AUR build concurrency

```toml
# ~/.config/omg/config.toml
[aur]
build_concurrency = 4
cache_builds = true
enable_ccache = true
enable_sccache = true
```

Choose concurrency based on both available memory and CPU cores. A compiler can use several cores within one build. Reduce concurrency if swapping or memory pressure increases. Compiler caches help only when the build and cache configuration permit reuse; no fixed percentage improvement is guaranteed.

Keep sandboxing and package review enabled. Native builds are not a routine performance recommendation because they execute package code with broader host access.

## Install packages in one transaction

```bash
omg install gcc clang rustup
```

Use a disposable Arch machine for this example. Independent package-manager processes compete for the package database lock. Do not run several background `omg install` processes to parallelize system mutations. AUR build concurrency is separate from transaction concurrency.

## Diagnose downloads

```bash
omg doctor --network
```

Check repository availability, mirror configuration, and network conditions before attributing download time to CLI overhead. Use the selected backend's supported mirror tools. Do not lower signature or provenance checks to improve timing.

## Use caches deliberately in CI

Cache only data the job needs. Avoid uploading the entire OMG data directory without review; it can contain audit history, account state, telemetry queues, and environment inventory. Partition caches by platform, backend, toolchain, and dependency inputs. Do not restore untrusted caches into privileged jobs.

## Keep scratch output off memory-backed temporary storage

Do not benchmark storage by writing large files to `/tmp`; it may be RAM-backed. Use a dedicated directory on the filesystem being measured and remove only scratch files you created. Store build targets and large test output under `~/.cache/build-targets/`.

## Report a regression

Include a reproducible command, before-and-after artifact identifiers, sample counts, raw timings, and relevant environment differences. Separate observed results from suspected causes. See [contributing](../CONTRIBUTING.md) for focused checks and [daemon behavior](./daemon.md) for fallback paths.
