import { describe, expect, test } from "bun:test";
import assert from "node:assert/strict";
import {
    cloudCiChecks,
    cloudCiPlanSha256,
    parseCloudCiRequest,
    verifyCloudCiReceipt,
    verifyCloudCiObjects,
} from "../../scripts/cloud-ci-evidence.mjs";

import { expectedCloudReports } from "../../services/cloud-ci/runner/plan.mjs";

const request = {
    repository: "omg-cli/omg",
    sha: "a".repeat(40),
    ref: "refs/heads/main",
    runId: "100",
    attempt: "1",
};

const policy = { imageDigest: `sha256:${"c".repeat(64)}` };
const id = `cl-${request.runId}-${request.attempt}-${request.sha}`;

const receipt = () => ({
    ...request,
    conclusion: "success",
    planSha256: cloudCiPlanSha256,
    imageDigest: policy.imageDigest,
    requiredChecks: cloudCiChecks,
    verificationReports: [],
    checks: cloudCiChecks.map((name) => ({
        name,
        exitCode: 0,
        stdoutKey: `logs/${id}/${name}.stdout`,
        stderrKey: `logs/${id}/${name}.stderr`,
        stdoutSha256: "d".repeat(64),
        stderrSha256: "e".repeat(64),
        reports: expectedCloudReports(name).map((name) => ({
            name,
            key: `reports/${id}/${name}`,
            sha256: "f".repeat(64),
        })),
    })),
});

describe("Cloudflare CI proof admission", () => {
    test("requires every actual report declared by the Rust plan", () => {
        for (const name of cloudCiChecks.filter((name) => expectedCloudReports(name).length)) {
            const value = receipt();
            value.checks.find((check) => check.name === name).reports = [];
            expect(() => verifyCloudCiReceipt(value, request, policy)).toThrow("required reports");
        }
    });
    test("rejects logs and reports borrowed from another run", () => {
        const value = receipt();
        value.checks[0].stdoutKey = "logs/another-run/frozen-dependencies.stdout";
        expect(() => verifyCloudCiReceipt(value, request, policy)).toThrow("object identity");
        const report = receipt();
        report.checks[0].reports.push({
            name: "portable-units.xml",
            key: "reports/other/portable-units.xml",
            sha256: "f".repeat(64),
        });
        expect(() => verifyCloudCiReceipt(report, request, policy)).toThrow("object identity");
    });

    test("downloads evidence and rejects altered bytes despite a success receipt", async () => {
        const value = receipt();
        const { createHash } = await import("node:crypto");
        const digest = createHash("sha256").update("actual evidence").digest("hex");

        for (const entry of value.checks) {
            entry.stdoutSha256 = digest;
            entry.stderrSha256 = digest;

            for (const report of entry.reports) report.sha256 = digest;
        }

        await verifyCloudCiObjects(value, async () => new Response("actual evidence"));
        await assert.rejects(
            () => verifyCloudCiObjects(value, async () => new Response("changed evidence")),
            /hash mismatch/,
        );
        await assert.rejects(
            () => verifyCloudCiObjects(value, async () => new Response("missing", { status: 404 })),
            /unavailable/,
        );
    });
    test("verification reports must exist, match the summary, and be fetched with exact bytes", async () => {
        const { createHash } = await import("node:crypto");
        const digest = (text) => createHash("sha256").update(text).digest("hex");
        const value = receipt();
        const proposalSha256 = "1".repeat(64);
        const verificationId = `${id}-v-${proposalSha256.slice(0, 16)}`;
        const objects = new Map();
        for (const check of value.checks) {
            check.stdoutKey = check.stdoutKey.replace(id, verificationId);
            check.stderrKey = check.stderrKey.replace(id, verificationId);
            check.stdoutSha256 = check.stderrSha256 = digest("log");
            objects.set(check.stdoutKey, "log");
            objects.set(check.stderrKey, "log");
            for (const report of check.reports) {
                report.key = report.key.replace(id, verificationId);
                report.sha256 = digest("check report");
                objects.set(report.key, "check report");
            }
        }
        value.verificationReports = ["baseline", "patched"].map((role) => {
            const name = `regression-${role}.json`;
            const content = JSON.stringify({ role, exitCode: role === "baseline" ? 101 : 0 });
            const key = `reports/${verificationId}/${name}`;
            objects.set(key, content);
            return { name, key, sha256: digest(content) };
        });
        value.verificationReceipt = Object.fromEntries(
            value.verificationReports.map((report, index) => [
                index === 0 ? "baseline" : "patched",
                { reportSha256: report.sha256 },
            ]),
        );
        const verificationPolicy = { ...policy, proposalSha256 };
        const admit = (candidate) => verifyCloudCiReceipt(candidate, request, verificationPolicy);
        assert.equal(admit(value), value);
        for (const invalid of [
            { ...value, verificationReports: undefined },
            { ...value, verificationReports: [] },
            {
                ...value,
                verificationReports: [value.verificationReports[0], value.verificationReports[0]],
            },
            {
                ...value,
                verificationReports: value.verificationReports.map((r) => ({
                    ...r,
                    key: r.key.replace(verificationId, "other"),
                })),
            },
            {
                ...value,
                verificationReports: value.verificationReports.map((r) => ({
                    ...r,
                    sha256: "2".repeat(64),
                })),
            },
        ])
            assert.throws(() => admit(invalid));
        assert.throws(() =>
            verifyCloudCiReceipt(
                { ...receipt(), verificationReports: value.verificationReports },
                request,
                policy,
            ),
        );
        const fetched = [];
        await verifyCloudCiObjects(value, async (key) => {
            fetched.push(key);
            return new Response(objects.get(key));
        });
        for (const report of value.verificationReports) {
            assert.ok(fetched.includes(report.key));
            await assert.rejects(
                () =>
                    verifyCloudCiObjects(value, async (key) =>
                        key === report.key
                            ? new Response("missing", { status: 404 })
                            : new Response(objects.get(key)),
                    ),
                /unavailable/,
            );
            await assert.rejects(
                () =>
                    verifyCloudCiObjects(
                        value,
                        async (key) =>
                            new Response(key === report.key ? "forged report" : objects.get(key)),
                    ),
                /hash mismatch/,
            );
        }
    });
    test("rejects an image mismatch and missing output hashes", () => {
        expect(() =>
            verifyCloudCiReceipt(
                { ...receipt(), imageDigest: `sha256:${"f".repeat(64)}` },
                request,
                policy,
            ),
        ).toThrow("image");
        expect(() =>
            verifyCloudCiReceipt(
                {
                    ...receipt(),
                    checks: receipt().checks.map((check) => ({
                        ...check,
                        stdoutSha256: undefined,
                    })),
                },
                request,
                policy,
            ),
        ).toThrow("checks");
    });
    test("rejects a success label with missing, repeated, or failed checks", () => {
        for (const checks of [
            [],
            [receipt().checks[0], receipt().checks[0]],
            receipt().checks.map((entry, index) => ({ ...entry, exitCode: index === 1 ? 1 : 0 })),
        ])
            expect(() => verifyCloudCiReceipt({ ...receipt(), checks }, request, policy)).toThrow(
                "checks",
            );
    });

    test("rejects evidence from another commit, branch, run, or attempt", () => {
        for (const [key, value] of Object.entries({
            sha: "b".repeat(40),
            ref: "refs/heads/prerelease",
            runId: "101",
            attempt: "2",
        }))
            expect(() =>
                verifyCloudCiReceipt({ ...receipt(), [key]: value }, request, policy),
            ).toThrow("identity");
    });

    test("accepts complete exact-run evidence and rejects unsupported requests", () => {
        expect(verifyCloudCiReceipt(receipt(), request, policy)).toEqual(receipt());
        expect(() => parseCloudCiRequest({ ...request, repository: "other/repo" })).toThrow();
        expect(() => parseCloudCiRequest({ ...request, sha: "main" })).toThrow();
        expect(() => parseCloudCiRequest({ ...request, ref: "refs/heads/ai-fix/patch" })).toThrow();
    });

    test("rejects a passing receipt produced by a different trusted plan", () => {
        expect(() =>
            verifyCloudCiReceipt({ ...receipt(), planSha256: "b".repeat(64) }, request, policy),
        ).toThrow("plan");
    });
});
