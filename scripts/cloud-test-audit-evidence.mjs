import { createHash } from "node:crypto";
import {
    parseTestAuditEvidence,
    testAuditDigest,
} from "../services/cloud-ci/src/test-audit-contract.ts";
import {
    testAuditPhasesFor,
    testAuditPhaseSource,
} from "../services/cloud-ci/runner/test-audit.mjs";
import {
    discoverRustTestArtifact,
    parseRustCatalog,
    parseRustExecution,
    rustProfile,
} from "../services/cloud-ci/runner/rust-evidence.mjs";
import {
    verifyCloudCiReceipt,
    verifyCloudCiObjects,
} from "./cloud-ci-evidence.mjs";

export async function verifyCloudTestAudit(receipt, request, policy, load) {
    const audit = request.testAudit;
    if (
        !audit ||
        audit.verifierRevision !== policy.verifierRevision ||
        receipt.verificationReceipt
    )
        throw new Error(
            "Existing-test audit requires its separate trusted verifier contract.",
        );
    const digest = testAuditDigest(audit.proposal);
    if (
        !receipt.testAudit ||
        receipt.testAudit.verifierRevision !== policy.verifierRevision ||
        testAuditDigest(receipt.testAudit.proposal) !== digest
    )
        throw new Error(
            "Existing-test audit request differs from its immutable receipt.",
        );
    verifyCloudCiReceipt(receipt, request, {
        ...policy,
        testAuditSha256: digest,
    });
    const evidence = parseTestAuditEvidence(request, receipt.testAuditReceipt);
    const id = `cl-${request.runId}-${request.attempt}-${request.sha}-ta-${digest.slice(0, 16)}`;
    const phases = testAuditPhasesFor(audit.proposal);
    const refs = receipt.testAuditReports;
    if (
        !Array.isArray(refs) ||
        refs.length !== phases.length ||
        new Set(refs.map((ref) => ref.name)).size !== phases.length
    )
        throw new Error("Exact existing-test audit phase reports required.");
    for (const phase of phases) {
        const name = `test-audit-${phase}.json`;
        const ref = refs.find((entry) => entry.name === name);
        if (
            !ref ||
            ref.key !== `reports/${id}/${name}` ||
            ref.sha256 !== evidence[phase].reportSha256
        )
            throw new Error("Existing-test audit report identity differs.");
        const response = await load(ref.key);
        if (!response.ok)
            throw new Error("Existing-test raw report unavailable.");
        const chunks = [];
        let total = 0;
        for await (const chunk of response.body) {
            total += chunk.byteLength;
            if (total > 20_000_000)
                throw new Error(
                    "Existing-test raw report exceeds byte budget.",
                );
            chunks.push(chunk);
        }
        const bytes = Buffer.concat(chunks);
        if (createHash("sha256").update(bytes).digest("hex") !== ref.sha256)
            throw new Error("Existing-test raw report hash differs.");
        const raw = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(bytes),
        );
        const { reportSha256, ...summary } = evidence[phase];
        const source = testAuditPhaseSource(audit.proposal, phase);
        if (raw.compiler?.exitCode !== 0 || raw.listing?.exitCode !== 0)
            throw new Error("Existing-test compiler or catalog did not pass.");
        const catalog = parseRustCatalog(
            raw.listing.stdout,
            audit.proposal.test.testName,
            { existingTest: true },
        );
        if (JSON.stringify(catalog) !== JSON.stringify(raw.catalog))
            throw new Error(
                "Existing-test raw catalog differs from its parsed listing.",
            );
        const parsed = parseRustExecution({
            ...raw.execution,
            testName: audit.proposal.test.testName,
            file: audit.proposal.test.path,
            source,
            catalog,
        });
        const artifact = discoverRustTestArtifact(
            raw.compiler.stdout,
            audit.proposal.test.path,
            { existingTest: true, target: audit.proposal.test.target },
        );
        const canonical = (value) =>
            JSON.stringify(value, (_, item) =>
                item && typeof item === "object" && !Array.isArray(item)
                    ? Object.fromEntries(
                          Object.entries(item).sort(([a], [b]) =>
                              a.localeCompare(b),
                          ),
                      )
                    : item,
            );
        if (
            Object.entries(parsed).some(
                ([key, value]) =>
                    key !== "reportSha256" && summary[key] !== value,
            ) ||
            artifact.compilerMessagesSha256 !==
                summary.compilerMessagesSha256 ||
            JSON.stringify(artifact) !== JSON.stringify(raw.artifact) ||
            JSON.stringify(raw.recipe.profile) !==
                JSON.stringify(rustProfile) ||
            JSON.stringify(raw.recipe.args) !==
                JSON.stringify([
                    "test",
                    ...(audit.proposal.test.target === "lib"
                        ? ["--lib"]
                        : [
                              "--test",
                              audit.proposal.test.path
                                  .split("/")
                                  .at(-1)
                                  .slice(0, -3),
                          ]),
                    "--no-run",
                    "--message-format=json",
                    "--no-default-features",
                    "--features",
                    "pgp,license",
                    "--locked",
                    "--offline",
                ]) ||
            !raw.recipe.rustc.includes("release: 1.95.0") ||
            !raw.recipe.cargo.startsWith("cargo 1.95.0") ||
            createHash("sha256").update(canonical(raw.recipe)).digest("hex") !==
                summary.recipeSha256
        )
            throw new Error(
                "Existing-test raw execution differs from the declared source or recipe.",
            );
        if (
            JSON.stringify(
                Object.keys(raw.result)
                    .sort()
                    .map((key) => [key, raw.result[key]]),
            ) !==
            JSON.stringify(
                Object.keys(summary)
                    .sort()
                    .map((key) => [key, summary[key]]),
            )
        )
            throw new Error(
                "Existing-test raw report differs from admitted summary.",
            );
    }
    await verifyCloudCiObjects({ ...receipt, testAuditReports: [] }, load);
    return evidence;
}
