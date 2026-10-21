import { expect, test } from "bun:test";
import * as reporting from "../runner/unit-report.mjs";

test("failed Rust diagnostics retain assertion messages after long test output", () => {
    expect(typeof reporting.summarizeUnitFailures).toBe("function");
    const report = { testsuites: { testsuite: [{ testcase: [
        { $: { name: "passing" } },
        { $: { name: "relative_fixture", classname: "omg::lib" },
          failure: [{ $: { message: "fixture directory failed" }, _: "Permission denied (os error 13)" }] },
    ] }] } };
    expect(reporting.summarizeUnitFailures(report)).toEqual({
        failed: 1, omitted: 0, failures: [{ name: "relative_fixture", classname: "omg::lib",
            message: "fixture directory failed", output: "Permission denied (os error 13)" }],
    });
});

test("Rust failure diagnostics stay bounded and report omitted cases", () => {
    expect(typeof reporting.summarizeUnitFailures).toBe("function");
    const report = { testsuites: { testsuite: [{ testcase: Array.from({ length: 20 }, (_, index) => ({
        $: { name: `case_${index}` }, error: [{ _: "\u0001".repeat(10000) }],
    })) }] } };
    const summary = reporting.summarizeUnitFailures(report);
    expect(summary.failed).toBe(20);
    expect(summary.omitted).toBe(20 - summary.failures.length);
    expect(summary.failures.length).toBeGreaterThan(0);
    expect(Buffer.byteLength(JSON.stringify(summary))).toBeLessThanOrEqual(12000);
});
