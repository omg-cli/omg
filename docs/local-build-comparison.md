# Compare Windows WHPX and GitHub Rust builds

Run these commands from the existing OMG checkout in Windows PowerShell. The local runner uses native QEMU with WHPX. It does not use WSL or create another worktree.

## Run the local measurement

Use the prepared Ubuntu 24.04 template and its existing tools and backing image. Keep the paths under `.git` on C:.

```powershell
python scripts/windows-build-comparison.py `
    --tools .git/local-consolidation-20261109/dependency-repair/windows-whpx-pilot/tools/msys64 `
    --image .git/local-consolidation-20261109/dependency-repair/windows-whpx-pilot/images/ubuntu-noble-20260926-amd64.qcow2 `
    --template .git/native-whpx-20261110/state/templates/ubuntu-8d07577e85afa903d68d6dcb886b93ae2928e3b169d2ae12f7232090a91367cd.qcow2 `
    --memory-mib 8192 `
    --source-sha 329ed5b7a2d01ce40cbe0b0b70f42d66cfebd0ee
```

The runner prints the path to its host receipt under `.git/native-whpx-20261110/state/comparison-*`. Read `guest-receipt.json` for individual measurements and `evidence.tar.gz` for logs. Accept a run only when both host and guest receipts report `complete`.

The current tool streams JSON phase starts and ends with labels. The published experiment used driver `12a972` and script SHA-256 `8547944aa09b09acf467abc4c3f4763bc221df89043e4c412e2771ed6161c11b`, before these progress records were added.

## Run the matching GitHub measurement

Dispatch the existing benchmark workflow from the branch containing the same comparison script.

```powershell
gh workflow run benchmark.yml --repo omg-cli/omg `
    --ref feat/native-windows-rust-guests `
    -f rust-comparison=true `
    -f source-sha=329ed5b7a2d01ce40cbe0b0b70f42d66cfebd0ee
```

Download the run's `rust-comparison-<run-id>-<attempt>` artifact. Compare its source SHA, source manifest SHA-256, archive SHA-256, and script SHA-256 with the local guest receipt before comparing times.

For a later experiment, supply the same new full source SHA to both commands. A blank GitHub `source-sha` uses the selected workflow commit. The `rust-comparison` input runs only this measurement job.

The prepared template must match the measured Cargo inputs. If those inputs change, prepare a matching template before the offline comparison.

## Read the measurements

Both environments use Rust 1.95.0, four Cargo jobs, and features `debian,pgp,license`. Builds and selected tests use the unchanged release profile, including fat LTO and one codegen unit.

The cold build starts with no compiled artifacts or compiler cache. Dependency sources are already prefetched. Package installation, downloads, guest boot, and source transfer are outside the measured commands. OS page caches remain populated.

Three warm builds repeat unchanged source and retain the target directory. Their median measures Cargo artifact reuse. It does not measure rebuild speed after an edit.

The Windows command creates a fresh disposable guest for each measurement wave. Warm samples share that guest's target directory. After evidence collection, the runner shuts down the guest and removes its overlay, including compiled targets. Separate invocations start compilation cold again; this command does not introduce a persistent compiled-artifact cache.

The two exact Debian library tests run after the four binary builds. The first test invocation includes the first libtest compilation. The second named test reuses that compilation. Three further pairs provide warm test measurements. Each test must execute once and pass. Both binaries must pass version and help checks, and `omg --json explicit` must match the native package inventory without changing installed packages.

The RSS value is the maximum process RSS reported by Linux `wait4`, in KiB. It is not aggregate simultaneous memory for all compiler processes. Windows QEMU memory and host pressure appear separately in the host receipt.

The local guest has four virtual CPUs and 8 GiB RAM. The GitHub plan has four CPUs and 16 GiB RAM. Check the recorded CPU count and memory before reporting results. CPU models, memory, storage, kernel, and package revisions can differ, so these timings compare the practical environments rather than isolate WHPX overhead.
