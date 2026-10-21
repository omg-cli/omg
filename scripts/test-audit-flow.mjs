export async function runTestAuditPage({
    collected,
    sha,
    branch,
    formatting,
    publishRequested,
    io,
}) {
    const report = {
        repository: "omg-cli/omg",
        branch,
        sha,
        baseSha: sha,
        sourceRange: collected.sourceRange,
        status: "reviewed",
        formatting,
        suppliedPaths: [],
        readPaths: [],
        unreviewedPaths: [],
        batches: [],
        publications: [],
        candidateOutcomes: [],
        testAudits: [],
        testAuditOutcomes: [],
        publishRequested,
        coverageMeaning:
            "Historical backlog names were reconciled to exact current file candidates. Only independently admitted exact test/fault execution earns bounded sensitivity credit. Held rows remain unresolved.",
    };
    for (const row of collected.rows) {
        if (row.status !== "selected") {
            report.unreviewedPaths.push({ path: row.id, reason: row.reason });
            report.testAuditOutcomes.push({
                id: row.id,
                status: "held",
                reason: row.reason,
            });
            continue;
        }
        report.suppliedPaths.push(row.task.path);
        try {
            const audit = await io.audit(row);
            if (audit) {
                report.readPaths.push(...(audit.readPaths ?? []));
                report.testAudits.push(audit);
                report.testAuditOutcomes.push({
                    id: row.id,
                    status:
                        audit.request.testAudit.proposal.purpose ===
                        "existing-test-sensitivity"
                            ? "verified-sensitivity"
                            : "verified-strengthening",
                    proofId: audit.id,
                });
            } else
                report.testAuditOutcomes.push({
                    id: row.id,
                    status: "no-supported-strengthening",
                });
        } catch (error) {
            report.testAuditOutcomes.push({
                id: row.id,
                status: "held",
                reason:
                    error instanceof Error
                        ? error.message
                        : "audit-operation-failed",
            });
        }
    }
    return report;
}
export function testAuditContinuation(report, currentSha, runId, attempt) {
    const range = report.sourceRange;
    const pageSize = range?.pageSize ?? 2;
    if (range?.kind !== "test-audit") return { status: "not-a-test-audit" };
    if (
        ![1, 2].includes(pageSize) ||
        report.repository !== "omg-cli/omg" ||
        report.branch !== "main" ||
        range.sha !== report.sha ||
        !/^([a-f0-9]{40})$/.test(report.sha) ||
        !/^[a-f0-9]{64}$/.test(range.inventoryDigest ?? "") ||
        !Number.isSafeInteger(range.cursor) ||
        range.cursor < 0 ||
        range.cursor % pageSize ||
        !Number.isSafeInteger(range.totalPaths) ||
        range.totalPaths < 1 ||
        range.totalPaths > 10000 ||
        range.cursor >= range.totalPaths ||
        range.pagePaths !==
            Math.min(pageSize, range.totalPaths - range.cursor) ||
        range.nextCursor !==
            (range.cursor + range.pagePaths < range.totalPaths
                ? range.cursor + range.pagePaths
                : null)
    )
        throw new Error("Test audit continuation inventory differs");
    if (!["reviewed", "no-reviewable-source"].includes(report.status))
        return { status: "incomplete-review-blocked" };
    if (currentSha !== report.sha) return { status: "incomplete-stale" };
    if (range.nextCursor === null) return { status: "inventory-exhausted" };
    if (
        !/^[1-9][0-9]{0,19}$/.test(runId ?? "") ||
        !/^[1-9][0-9]{0,5}$/.test(attempt ?? "")
    )
        throw new Error("Invalid test audit run identity");
    return {
        status: "continue",
        inputs: {
            branch: "main",
            scope: "test-audit",
            publish: String(report.publishRequested === true),
            audit_sha: report.sha,
            audit_digest: range.inventoryDigest,
            audit_cursor: String(range.nextCursor),
            audit_parent: `${runId}-${attempt}`,
        },
    };
}
