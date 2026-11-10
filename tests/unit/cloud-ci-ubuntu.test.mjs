import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { expectedCloudChecks, expectedCloudReports, planIdentity, selectCloudPlan } from "../../services/cloud-ci/runner/plan.mjs";
import { admitCloudCiRuntime, cloudCiTarget, verifyCloudCiReceipt, verifyCloudCiObjects } from "../../scripts/cloud-ci-evidence.mjs";

const hash = text => createHash("sha256").update(text).digest("hex");
const workload = "ubuntu-native-pilot";
const source = { repository: "omg-cli/omg", sha: "a".repeat(40), ref: "refs/heads/main", runId: "123", attempt: "1" };
const id = `cl-123-1-${source.sha}`;
const imageDigest = `sha256:${"b".repeat(64)}`;

test("pilot selection preserves the production plan and restricts endpoints and reports", () => {
    expect(hash(planIdentity)).toBe("1644acd479f1562142a6faa2069f082b7cd6c246cf83fdc2fffc7026a554ef5f");
    expect(expectedCloudChecks(source.ref, workload)).toEqual(["frozen-dependencies", "source-format", "ubuntu-native-readonly"]);
    expect(expectedCloudReports("ubuntu-native-readonly", workload)).toEqual(["ubuntu-native.json", "ubuntu-daemon.json"]);
    expect(() => expectedCloudReports("ubuntu-native-readonly")).toThrow();
    expect(() => expectedCloudChecks("refs/heads/untrusted", workload)).toThrow();
    expect(() => cloudCiTarget("arbitrary-shell")).toThrow();
    expect(cloudCiTarget(workload)).toEqual({ service: "omg-cloud-ci-ubuntu-pilot", endpoint: "https://omg-cloud-ci-ubuntu-pilot.latham.workers.dev/" });
    const runtime = { ok: true, engine: "@cloudflare/ci@0.2.0", planSha256: hash(selectCloudPlan(workload).identity) };
    expect(() => admitCloudCiRuntime(runtime, workload)).not.toThrow();
    expect(() => admitCloudCiRuntime(runtime)).toThrow();
});

test("matching artifact hashes cannot admit a failed native behavior report", async () => {
    const objects = new Map();
    const checks = expectedCloudChecks(source.ref, workload).map(name => {
        const stdoutKey = `logs/${id}/${name}.stdout`;
        const stderrKey = `logs/${id}/${name}.stderr`;
        objects.set(stdoutKey, "executed");
        objects.set(stderrKey, "");
        const reports = expectedCloudReports(name, workload).map(report => {
            const key = `reports/${id}/${report}`;
            const content = report === "ubuntu-native.json" ? '{"accepted":false}' : '{}';
            objects.set(key, content);
            return { name: report, key, sha256: hash(content) };
        });
        return { name, exitCode: 0, stdoutKey, stderrKey, stdoutSha256: hash("executed"), stderrSha256: hash(""), reports };
    });
    const receipt = { ...source, conclusion: "success", imageDigest, planSha256: hash(selectCloudPlan(workload).identity),
        requiredChecks: checks.map(check => check.name), checks, verificationReports: [] };
    expect(() => verifyCloudCiReceipt(receipt, source, { imageDigest })).toThrow();
    expect(() => verifyCloudCiReceipt(receipt, source, { imageDigest, workload })).not.toThrow();
    await expect(verifyCloudCiObjects(receipt, key => new Response(objects.get(key)), { workload })).rejects.toThrow("Native source identity mismatch");
});
