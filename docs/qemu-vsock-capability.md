# Ordinary-user vsock capability reporter

Run `python3 -B scripts/probe-qemu-vsock.py` as the existing ordinary host user. This optional diagnostic does not install tools, change permissions or Docker policy, assign a guest CID, start a VM, forward traffic or change the default transport.

The reporter uses Linux's installed UAPI headers and existing C compiler. It opens the existing character device with no-follow/nonblocking flags, claims only its own descriptor, reads vhost features, closes and verifies release. It separately creates an AF_VSOCK stream, binds host CID 2 to a kernel-selected ephemeral port, listens and closes. No connection is accepted and no endpoint remains afterward.

Compilation is bounded to 30 seconds, execution to 5 seconds, compiler identity to 5 seconds, and combined stdout/stderr to 64 KiB per owned child. A deadline or output overflow kills the owned process group and waits for its direct child. Temporary source, executable and output files are removed on every normal or exception path. Source is copied into the private temporary directory before compilation and hashed; binary and reporter identities are included.

Interpret the JSON, not just the process exit code:

- `available`: actual ordinary-user device ownership/features and host socket operations all succeeded. Guest transport remains unproved.
- `refused`: an actual operation returned EPERM or EACCES.
- `unavailable`: the actual probe could not establish both interfaces; syscall errno/results remain available.
- `unqualified`: root was deliberately refused as evidence for the ordinary-runner contract.
- `unprobed`: no existing compiler was available. This says nothing about kernel capabilities.
- `unsupported`: the host is not Linux.
- `harness_error`: compilation, execution, output or identity checks failed. Exit 2 and complete=false preserve this failure.

Before using a hosted receipt, reconcile its C/reporter hashes with immutable source, its original job/run/attempt, native artifact identity and effective UID/GID. Local availability and compiler success do not establish hosted adoption. A relay still needs a privately owned endpoint, unique guest CID, strict authenticated SSH, bounded lifecycle/reap, genuine cross-distro/no-NIC clone trials and independent confinement/egress controls. The default maintained libslirp path stays in place until those gates pass.

Linux process ownership checks: `python3 -B scripts/test_qemu_vsock_probe.py`. They execute real children for deadline, output overflow, fast-exit overflow, and nonzero exit/stream preservation.

Primary contracts: [Linux vsock socket ABI](https://man7.org/linux/man-pages/man7/vsock.7.html), [Linux 6.18 vhost-vsock implementation](https://github.com/torvalds/linux/blob/v6.18/drivers/vhost/vsock.c), [Linux vhost UAPI](https://github.com/torvalds/linux/blob/v6.18/include/uapi/linux/vhost.h).
