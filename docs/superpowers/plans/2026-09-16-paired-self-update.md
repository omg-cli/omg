# Paired OMG self-update

The existing updater discards omgd from the verified archive and replaces only omg.

1. Require regular, unique omg and omgd payloads from the same checksum/provenance-verified archive. Preserve traversal, size, and entry-count bounds. Package omgd on macOS as well as Linux.
2. Serialize updaters using a destination-directory lock. Stage and sync both payloads and rollback copies before replacing either destination. Reject symlink/non-regular destinations. Restore old files on replacement or directory-sync errors; preserve recovery files if rollback fails.
3. Report both installed binaries and explicitly require restart of any already-running daemon. Do not kill processes by name or silently restart another user's service.
4. Test pair extraction, missing/duplicate/link payloads, successful pair installation, absent old daemon, preflight failure, injected second-replacement failure, and concurrent update exclusion. Run narrow local checks and hosted Linux tests.

Individual renames are atomic; two filenames are not one atomic filesystem transaction. This change handles reported I/O failures, not arbitrary power loss between renames. Do not describe it as an atomic pair update.

References: [tempfile persist semantics](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html#method.persist), [rename and existing open files](https://man7.org/linux/man-pages/man2/rename.2.html).
