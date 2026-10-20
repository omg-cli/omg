import { expect, test } from "bun:test";
import { cleanupUnitReportEvidence } from "../runner/unit-report-evidence.mjs";

test("evidence cleanup failures are observable and sanitized without masking the original result", () => {
    const warnings = [];
    const original = { status: "missing", bytes: 0 };
    const closed = [];
    const result = (() => {
        try {
            return original;
        } finally {
            cleanupUnitReportEvidence([4, 5], true, {
                close(fd) {
                    closed.push(fd);
                    throw new Error("private-close-detail");
                },
                remove() {
                    throw new Error("private-remove-detail");
                },
                warn(value) {
                    warnings.push(value);
                },
            });
        }
    })();
    expect(result).toBe(original);
    expect(closed).toEqual([4, 5]);
    expect(warnings.map((value) => JSON.parse(value))).toEqual([
        { event: "cloud-ci-evidence-cleanup-failed", operation: "close" },
        { event: "cloud-ci-evidence-cleanup-failed", operation: "close" },
        { event: "cloud-ci-evidence-cleanup-failed", operation: "remove" },
    ]);
    expect(warnings.join()).not.toContain("private-");
});
