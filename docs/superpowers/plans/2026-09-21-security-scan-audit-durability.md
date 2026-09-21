# Security scan completion and audit durability (#478)

The current shared scan queues its completion record on a detached audit writer, then returns success. Hosted coverage and native Debian both failed because the in-process TUI test removed its fixture while a late writer recreated audit files. A deterministic regression holds the audit file lock and proves the old scan returns success even though its record cannot be written.

Implement completion persistence on an awaited blocking worker, capturing the destination before scheduling. Preserve the existing cross-process file lock, hash chain, bounded fields and fsync in AuditLogger. Both native and generic scan paths must await it. A write or corrupt-log error must be returned with context instead of reporting a fully completed audit. Do not suppress fixture cleanup failures or add test retries/sleeps.

Verify: the held-lock scan remains pending, then completes after unlock with an integrity-valid record; failed inventory contributes no completion record; recovery contributes exactly one more. Add write-refusal evidence and direct-CLI persistence evidence. Run the isolated suite, relevant scan/logger unit tests, formatting/Clippy, then fresh hosted gates. This fixes scan completion semantics, not all detached daemon-event shutdown behavior.
