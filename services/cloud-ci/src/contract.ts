import { z } from "zod";
import { createHash } from "node:crypto";
import type { CiParams, CloudflareArtifacts } from "@cloudflare/ci";
import { testAuditSchema, testAuditDigest } from "./test-audit-contract";
import {
    boundedText,
    sha40,
    sha64,
    regressionPath,
    sourcePath,
    verificationSchema,
} from "./verification-schema";

export { verificationSchema } from "./verification-schema";

export const source = {
    namespace: "omg-ci",
    repo: "omg",
    repository: "omg-cli/omg",
};

const startSchema = z
    .strictObject({
        repository: z.literal("omg-cli/omg"),
        sha: z.string().regex(/^[a-f0-9]{40}$/),
        sourceBaseSha: sha40.optional(),
        ref: z.literal("refs/heads/main"),
        runId: z.string().regex(/^[1-9][0-9]{0,19}$/),
        attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
        verification: verificationSchema.optional(),
        testAudit: testAuditSchema.optional(),
    })
    .refine((request) => {
        const verification = request.verification;

        if (request.testAudit) return !verification && Number.isSafeInteger(Number(request.runId)) &&
            request.testAudit.proposal.baseSha === request.sha && request.ref === "refs/heads/main";
        if (!verification) return true;

        return (
            Number.isSafeInteger(Number(request.runId)) &&
            verification.proposal.baseSha === request.sha &&
            verification.proposal.branch === request.ref.slice(11) &&
            verification.regression.path ===
                `tests/ai-review-${verification.proposal.finding.key.slice(0, 16)}-${request.sha.slice(0, 12)}.rs`
        );
    }, "Verification identity mismatch")
    .refine(
        (request) => new TextEncoder().encode(JSON.stringify(request)).length <= (request.testAudit ? 1024 * 1024 : 65536),
        "CI request exceeds its purpose byte budget",
    );

export type StartRequest = z.infer<typeof startSchema>;

export const parseStart = startSchema.parse.bind(startSchema);

const canonicalObjectSchema = z.record(z.string(), z.unknown());

export const proposalDigest = (proposal: NonNullable<StartRequest["verification"]>["proposal"]) =>
    createHash("sha256")
        .update(
            JSON.stringify(proposal, (_, value) => {
                const parsed = canonicalObjectSchema.safeParse(value);

                return parsed.success
                    ? Object.fromEntries(
                          Object.entries(parsed.data).sort(([left], [right]) =>
                              left.localeCompare(right),
                          ),
                      )
                    : value;
            }),
        )
        .digest("hex");

const verificationSuffix = (request: StartRequest) =>
    request.testAudit ? `-ta-${testAuditDigest(request.testAudit.proposal).slice(0, 16)}` :
    request.verification ? `-v-${proposalDigest(request.verification.proposal).slice(0, 16)}` : "";

export const runIdentity = (request: StartRequest) =>
    `cl-${request.runId}-${request.attempt}-${request.sha}${verificationSuffix(request)}`;

export const receiptKey = (request: StartRequest) =>
    `receipts/${request.runId}-${request.attempt}/${request.sha}${verificationSuffix(request)}.json`;

export const requestKey = (id: string) => `runs/${id}/request.json`;
export const terminalSuccess = (status: string) => status === "complete";

const regressionEvidence = {
    testName: boundedText(200),
    exitCode: z.number().int().nonnegative(),
    tests: z.number().int().positive(),
    failures: z.number().int().nonnegative(),
    errors: z.literal(0),
    skipped: z.literal(0),
    reportSha256: sha64,
    stdoutSha256: sha64,
    stderrSha256: sha64,
    catalogSha256: sha64,
    executableSha256: sha64,
    compilerMessagesSha256: sha64,
    sourceSha256: sha64,
    recipeSha256: sha64,
};

const verificationEvidenceSchema = z.strictObject({
    repository: z.literal("omg-cli/omg"),
    branch: z.literal("main"),
    baseSha: sha40,
    proposalSha256: sha64,
    verifierRevision: sha40,
    runId: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    runAttempt: z.number().int().positive(),
    baseline: z.strictObject({
        ...regressionEvidence,
        assertionFailure: boundedText(4000),
        assertionFile: regressionPath,
        assertionLine: z.number().int().positive(),
        assertionSourceSha256: sha64,
    }),
    patched: z.strictObject(regressionEvidence),
    protectedPathsUnchanged: z.literal(true),
    changedPaths: z
        .array(z.union([sourcePath, regressionPath]))
        .min(2)
        .max(8),
    fileHashes: z
        .array(z.strictObject({ path: z.union([sourcePath, regressionPath]), sha256: sha64 }))
        .min(2)
        .max(8),
});

export function parseVerificationEvidence(
    request: StartRequest,
    input: z.infer<ReturnType<typeof z.json>>,
) {
    const evidence = verificationEvidenceSchema.parse(input);
    const verification = request.verification;

    if (
        !verification ||
        evidence.repository !== request.repository ||
        evidence.baseSha !== request.sha ||
        evidence.branch !== request.ref.slice(11) ||
        evidence.runId !== Number(request.runId) ||
        evidence.runAttempt !== Number(request.attempt) ||
        evidence.verifierRevision !== verification.verifierRevision ||
        evidence.proposalSha256 !== proposalDigest(verification.proposal) ||
        evidence.baseline.testName !== verification.regression.testName ||
        evidence.baseline.exitCode === 0 ||
        evidence.baseline.exitCode !== 101 ||
        evidence.baseline.tests !== 1 ||
        evidence.baseline.failures !== 1 ||
        evidence.baseline.assertionFile !== verification.regression.path ||
        evidence.patched.testName !== evidence.baseline.testName ||
        evidence.patched.tests !== evidence.baseline.tests ||
        evidence.patched.exitCode !== 0 ||
        evidence.patched.failures !== 0
    )
        throw new Error("Regression evidence does not admit this proposal");

    const testChange = verification.proposal.changes.find(
        (change) => change.path === verification.regression.path,
    );
    const sourceLine = testChange?.newContent.split(/\r?\n/)[evidence.baseline.assertionLine - 1];
    if (
        !testChange ||
        !sourceLine ||
        evidence.baseline.recipeSha256 !== evidence.patched.recipeSha256 ||
        evidence.baseline.sourceSha256 !==
            createHash("sha256").update(testChange.newContent).digest("hex") ||
        evidence.patched.sourceSha256 !== evidence.baseline.sourceSha256 ||
        evidence.baseline.assertionSourceSha256 !==
            createHash("sha256").update(sourceLine).digest("hex") ||
        !/^\s*assert(?:_eq|_ne)?!\s*\(/.test(sourceLine)
    )
        throw new Error("Rust source assertion or compiler recipe differs from the proposal");

    const expected = verification.proposal.changes
        .map(({ path, sha256 }) => ({ path, sha256 }))
        .sort((left, right) => left.path.localeCompare(right.path));

    if (
        JSON.stringify(
            evidence.fileHashes.toSorted((left, right) => left.path.localeCompare(right.path)),
        ) !== JSON.stringify(expected) ||
        JSON.stringify(evidence.changedPaths.toSorted()) !==
            JSON.stringify(expected.map(({ path }) => path).toSorted())
    )
        throw new Error("Regression evidence differs from declared proposal bytes");

    return evidence;
}

export function nativeParams(request: StartRequest): CiParams<CloudflareArtifacts> {
    return {
        provider: "cloudflare-artifacts",
        providerData: { namespace: source.namespace },
        owner: source.namespace,
        repo: source.repo,
        sha: request.sha,
        ref: request.ref,
        branch: request.ref.slice(11),
        trigger: "push",
        event: { type: "push" },
        remote: "cloudflare",
    };
}
