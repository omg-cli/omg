import { createHash } from "node:crypto";
import { testAuditDigest } from "../../../services/cloud-ci/src/test-audit-contract.ts";
import { testAuditPhasesFor } from "../../../services/cloud-ci/runner/test-audit.mjs";
import {
    discoverRustTestArtifact,
    parseRustCatalog,
    parseRustExecution,
    rustReport,
    rustProfile,
} from "../../../services/cloud-ci/runner/rust-evidence.mjs";
import {
    cloudCiChecks,
    cloudCiPlanSha256,
} from "../../../scripts/cloud-ci-evidence.mjs";
import { expectedCloudReports } from "../../../services/cloud-ci/runner/plan.mjs";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const blob = (value) =>
    createHash("sha1")
        .update(`blob ${Buffer.byteLength(value)}\0`)
        .update(value)
        .digest("hex");
const canonical = (value) =>
    JSON.stringify(value, (_, item) =>
        item && typeof item === "object" && !Array.isArray(item)
            ? Object.fromEntries(
                  Object.entries(item).sort(([a], [b]) => a.localeCompare(b)),
              )
            : item,
    );
export function testAuditProofFixture({
    sensitivity = false,
    paddingBytes = 0,
} = {}) {
    if (
        !Number.isSafeInteger(paddingBytes) ||
        paddingBytes < 0 ||
        paddingBytes > 210 * 1024
    )
        throw new Error("Invalid fixture padding budget");
    const padding = paddingBytes
        ? "//" + "p".repeat(Math.max(0, paddingBytes - 3)) + "\n"
        : "";
    const assertionLine = 4 + (paddingBytes ? 1 : 0);
    const original =
        padding +
        "#[test]\nfn checks_value() {\n    let value = 1;\n    assert!(value > 0);\n}\n";
    const stronger = original.replace(
        "    assert!(value > 0);",
        "    assert_eq!(value, 1);\n    assert!(value > 0);",
    );
    const production = "pub const VALUE: u32 = 1;\n";
    const proposal = {
        purpose: sensitivity
            ? "existing-test-sensitivity"
            : "existing-test-strengthening",
        repository: "omg-cli/omg",
        branch: "main",
        baseSha: "a".repeat(40),
        test: {
            path: "tests/value.rs",
            testName: "checks_value",
            originalBlobSha: blob(original),
            originalContent: original,
            newContent: sensitivity ? original : stronger,
            sha256: hash(sensitivity ? original : stronger),
            assertionLine,
        },
        fault: {
            path: "src/value.rs",
            originalBlobSha: blob(production),
            oldContentQuote: "VALUE: u32 = 1",
            newContent: production.replace("= 1", "= 2"),
            sha256: hash(production.replace("= 1", "= 2")),
        },
    };
    const policy = {
        endpoint: "https://omg-cloud-ci.latham.workers.dev/",
        imageDigest: `sha256:${"c".repeat(64)}`,
        verifierRevision: "d".repeat(40),
    };
    const request = {
        repository: "omg-cli/omg",
        sha: proposal.baseSha,
        ref: "refs/heads/main",
        runId: "42",
        attempt: "1",
        testAudit: { proposal, verifierRevision: policy.verifierRevision },
    };
    const id = `cl-42-1-${request.sha}-ta-${testAuditDigest(proposal).slice(0, 16)}`;
    const objects = new Map();
    const recipe = {
        args: [
            "test",
            "--test",
            "value",
            "--no-run",
            "--message-format=json",
            "--no-default-features",
            "--features",
            "pgp,license",
            "--locked",
            "--offline",
        ],
        profile: rustProfile,
        rustc: "rustc 1.95.0\nrelease: 1.95.0\n",
        cargo: "cargo 1.95.0\n",
    };
    const compiler = {
        stdout:
            JSON.stringify({
                reason: "compiler-artifact",
                profile: { test: true },
                target: {
                    name: "value",
                    kind: ["test"],
                    src_path: "/workspace/tests/value.rs",
                },
                features: rustProfile.expandedFeatures,
                executable: "/workspace/target/debug/deps/value-fixture",
                package_id: "path+file:///workspace#omg@0.1.0",
            }) +
            "\n" +
            JSON.stringify({ reason: "build-finished", success: true }) +
            "\n",
        stderr: "",
        exitCode: 0,
    };
    const artifact = discoverRustTestArtifact(
        compiler.stdout,
        proposal.test.path,
    );
    const listing = { stdout: "checks_value: test\n", stderr: "", exitCode: 0 };
    const catalog = parseRustCatalog(listing.stdout, "checks_value", {
        existingTest: true,
    });
    const phases = {},
        testAuditReports = [];
    for (const phase of testAuditPhasesFor(proposal)) {
        const red = phase === (sensitivity ? "oldFault" : "strongerFault"),
            source = phase.startsWith("old") ? original : stronger;
        const execution = {
            stdout: `running 1 test\ntest checks_value ... ${red ? "FAILED" : "ok"}\ntest result: ${red ? "FAILED. 0 passed; 1 failed" : "ok. 1 passed; 0 failed"}; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n`,
            stderr: red
                ? `thread 'checks_value' panicked at tests/value.rs:${assertionLine}:5:\nassertion \`left == right\` failed\n  left: 2\n right: 1\n`
                : "",
            exitCode: red ? 101 : 0,
        };
        const parsed = parseRustExecution({
            ...execution,
            testName: "checks_value",
            file: proposal.test.path,
            source,
            catalog,
        });
        const result = {
            ...parsed,
            executableSha256: hash("compiled fixture"),
            compilerMessagesSha256: artifact.compilerMessagesSha256,
            sourceSha256: hash(source),
            recipeSha256: hash(canonical(recipe)),
        };
        const report = rustReport(result, {
            artifact,
            recipe,
            catalog,
            compiler,
            listing,
            execution,
        });
        phases[phase] = report.result;
        const name = `test-audit-${phase}.json`,
            key = `reports/${id}/${name}`;
        objects.set(key, report.content);
        testAuditReports.push({ name, key, sha256: hash(report.content) });
    }
    const checks = cloudCiChecks.map((name) => {
        const stdoutKey = `logs/${id}/${name}.stdout`,
            stderrKey = `logs/${id}/${name}.stderr`;
        objects.set(stdoutKey, "fixture stdout");
        objects.set(stderrKey, "");
        return {
            name,
            exitCode: 0,
            stdoutKey,
            stderrKey,
            stdoutSha256: hash("fixture stdout"),
            stderrSha256: hash(""),
            reports: expectedCloudReports(name).map((name) => {
                const key = `reports/${id}/${name}`;
                objects.set(key, "fixture portable report");
                return { name, key, sha256: hash("fixture portable report") };
            }),
        };
    });
    const testAuditReceipt = {
        purpose: proposal.purpose,
        repository: request.repository,
        branch: "main",
        baseSha: request.sha,
        proposalSha256: testAuditDigest(proposal),
        verifierRevision: policy.verifierRevision,
        runId: 42,
        runAttempt: 1,
        ...phases,
        protectedPathsUnchanged: true,
        faultRestored: true,
        changedPaths: sensitivity ? [] : [proposal.test.path],
        fileHashes: sensitivity
            ? []
            : [{ path: proposal.test.path, sha256: proposal.test.sha256 }],
    };
    const receipt = {
        ...request,
        id,
        conclusion: "success",
        imageDigest: policy.imageDigest,
        planSha256: cloudCiPlanSha256,
        requiredChecks: cloudCiChecks,
        checks,
        verificationReports: [],
        testAuditReceipt,
        testAuditReports,
    };
    const load = async (key) =>
        objects.has(key)
            ? new Response(objects.get(key))
            : new Response("missing", { status: 404 });
    return {
        request,
        proposal,
        receipt,
        policy,
        objects,
        load,
        id,
        original,
        production,
    };
}
