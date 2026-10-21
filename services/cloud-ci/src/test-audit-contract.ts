import { z } from "zod";
import { createHash } from "node:crypto";
import { sha40, sha64, boundedText, sourcePath } from "./verification-schema";
import { validateTestAuditProposal, testAuditPhaseSource } from "../runner/test-audit.mjs";

const testPath = z.string().max(240).regex(/^tests\/[A-Za-z0-9_-]+\.rs$/);
const exactName = boundedText(200).regex(/^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$/);
export const testAuditSchema = z.strictObject({
    verifierRevision: sha40,
    proposal: z.strictObject({
        purpose: z.enum(["existing-test-strengthening", "existing-test-sensitivity"]),
        repository: z.literal("omg-cli/omg"), branch: z.literal("main"), baseSha: sha40,
        test: z.strictObject({ path: z.union([testPath, sourcePath]), target: z.literal("lib").optional(), testName: exactName, originalBlobSha: sha40,
            originalContent: boundedText(256 * 1024), newContent: boundedText(256 * 1024), sha256: sha64,
            assertionLine: z.number().int().positive().safe() }),
        fault: z.strictObject({ path: sourcePath, originalBlobSha: sha40, oldContentQuote: boundedText(4000),
            newContent: boundedText(256 * 1024), sha256: sha64 }),
    }).superRefine((proposal, context) => {
        try { validateTestAuditProposal(proposal); }
        catch (error) { context.addIssue({ code: "custom", message: error instanceof Error ? error.message : "Invalid test audit" }); }
    }),
});

export type TestAudit = z.infer<typeof testAuditSchema>;
const hash = (content: string) => createHash("sha256").update(content).digest("hex");
export const testAuditDigest = (proposal: TestAudit["proposal"]) => hash(JSON.stringify(proposal, (_, value: unknown) => {
    if (value && typeof value === "object" && !Array.isArray(value))
        return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)));
    return value;
}));
const result = z.strictObject({
    testName: exactName, exitCode: z.union([z.literal(0), z.literal(101)]), tests: z.literal(1),
    failures: z.union([z.literal(0), z.literal(1)]), errors: z.literal(0), skipped: z.literal(0),
    reportSha256: sha64, stdoutSha256: sha64, stderrSha256: sha64, catalogSha256: sha64,
    executableSha256: sha64, compilerMessagesSha256: sha64, sourceSha256: sha64, recipeSha256: sha64,
    assertionFailure: boundedText(4000).optional(), assertionFile: z.union([testPath, sourcePath]).optional(),
    assertionLine: z.number().int().positive().safe().optional(), assertionSourceSha256: sha64.optional(),
});
const receiptIdentity = {
    repository: z.literal("omg-cli/omg"), branch: z.literal("main"),
    baseSha: sha40, proposalSha256: sha64, verifierRevision: sha40,
    runId: z.number().int().positive().safe(), runAttempt: z.number().int().positive().safe(),
    oldIntact: result, oldFault: result,
    protectedPathsUnchanged: z.literal(true), faultRestored: z.literal(true),
};
export const strengtheningReceiptSchema = z.strictObject({
    ...receiptIdentity, purpose: z.literal("existing-test-strengthening"), strongerFault: result, strongerIntact: result,
    changedPaths: z.array(z.union([testPath, sourcePath])).length(1),
    fileHashes: z.array(z.strictObject({ path: z.union([testPath, sourcePath]), sha256: sha64 })).length(1),
});
const sensitivityReceiptSchema = z.strictObject({
    ...receiptIdentity, purpose: z.literal("existing-test-sensitivity"), changedPaths: z.array(z.never()).length(0), fileHashes: z.array(z.never()).length(0),
});
export const testAuditReceiptSchema = z.discriminatedUnion("purpose", [strengtheningReceiptSchema, sensitivityReceiptSchema]);
export type TestAuditReceipt = z.infer<typeof testAuditReceiptSchema>;
export function testAuditStateEntries(receipt: TestAuditReceipt) {
    const old = [{ phase: "oldIntact", evidence: receipt.oldIntact }, { phase: "oldFault", evidence: receipt.oldFault }];
    return receipt.purpose === "existing-test-sensitivity" ? old : [...old,
        { phase: "strongerFault", evidence: receipt.strongerFault }, { phase: "strongerIntact", evidence: receipt.strongerIntact }];
}

export function parseTestAuditEvidence(request: { repository: string; sha: string; ref: string; runId: string; attempt: string; testAudit?: TestAudit }, input: unknown) {
    const receipt = testAuditReceiptSchema.parse(input);
    const audit = request.testAudit;
    if (!audit || receipt.repository !== request.repository || request.ref !== "refs/heads/main" ||
        receipt.baseSha !== request.sha || audit.proposal.baseSha !== request.sha ||
        receipt.runId !== Number(request.runId) || receipt.runAttempt !== Number(request.attempt) ||
        receipt.verifierRevision !== audit.verifierRevision || receipt.proposalSha256 !== testAuditDigest(audit.proposal) || receipt.purpose !== audit.proposal.purpose)
        throw new Error("Existing-test audit receipt identity mismatch");
    for (const { phase, evidence: entry } of testAuditStateEntries(receipt)) {
        const red = receipt.purpose === "existing-test-sensitivity" ? phase === "oldFault" : phase === "strongerFault";
        if (entry.exitCode !== (red ? 101 : 0) || entry.failures !== (red ? 1 : 0) ||
            entry.testName !== audit.proposal.test.testName || entry.recipeSha256 !== receipt.oldIntact.recipeSha256 ||
            entry.sourceSha256 !== hash(testAuditPhaseSource(audit.proposal, phase as "oldIntact" | "oldFault" | "strongerFault" | "strongerIntact")))
            throw new Error("Existing-test audit state differs from the declared comparison");
    }
    const red = receipt.purpose === "existing-test-sensitivity" ? receipt.oldFault : receipt.strongerFault;
    const expectedPaths = receipt.purpose === "existing-test-sensitivity" ? [] : [audit.proposal.test.path];
    const expectedHashes = receipt.purpose === "existing-test-sensitivity" ? [] : [{ path: audit.proposal.test.path, sha256: audit.proposal.test.sha256 }];
    if (!red.assertionFailure || red.assertionFile !== audit.proposal.test.path || red.assertionLine !== audit.proposal.test.assertionLine ||
        red.assertionSourceSha256 !== hash(audit.proposal.test.newContent.split(/\r?\n/)[audit.proposal.test.assertionLine - 1]!) ||
        JSON.stringify(receipt.changedPaths) !== JSON.stringify(expectedPaths) || JSON.stringify(receipt.fileHashes) !== JSON.stringify(expectedHashes))
        throw new Error("Existing-test audit intended assertion or published test differs");
    return receipt;
}
