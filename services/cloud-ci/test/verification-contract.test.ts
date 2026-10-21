import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import {
    parseStart,
    parseVerificationEvidence,
    proposalDigest,
    runIdentity,
    receiptKey,
} from "../src/contract";

const sha = "a".repeat(40);
const key = "b".repeat(64);

const regression = {
    path: `tests/ai-review-${key.slice(0, 16)}-${sha.slice(0, 12)}.rs`,
    testName: "reproduces_defect",
};

const proposal = {
    repository: "omg-cli/omg" as const,
    branch: "main" as const,
    baseSha: sha,
    finding: {
        key,
        title: "Defect",
        summary: "Observed defect",
        path: "src/example.rs",
        line: 1,
        sourceQuote: "old",
        reproduction: "assert",
    },
    changes: [
        {
            path: "src/example.rs",
            originalBlobSha: sha,
            oldContentQuote: "old",
            newContent: "new",
            sha256: key,
        },
        {
            path: regression.path,
            originalBlobSha: null,
            oldContentQuote: "",
            newContent: "#[test]\nfn reproduces_defect() {\n assert_eq!(41,42);\n}\n",
            sha256: key,
        },
    ],
};

const request = {
    repository: proposal.repository,
    sha,
    ref: "refs/heads/main",
    runId: "123",
    attempt: "1",
    verification: { proposal, regression, verifierRevision: "c".repeat(40) },
};

test("accepts a bounded verification request bound to the exact source and designated regression", () => {
    expect(parseStart(request).verification).toEqual(request.verification);

    const alternate = parseStart({
        ...request,
        verification: {
            ...request.verification,
            proposal: {
                ...proposal,
                finding: { ...proposal.finding, summary: "Another candidate" },
            },
        },
    });

    expect(runIdentity(alternate)).not.toBe(runIdentity(parseStart(request)));
    expect(receiptKey(alternate)).not.toBe(receiptKey(parseStart(request)));
});

test("admits only exact red/green evidence bound to the proposal and trusted execution identity", () => {
    const parsed = parseStart(request);

    const result = {
        testName: regression.testName,
        exitCode: 0,
        tests: 1,
        failures: 0,
        errors: 0,
        skipped: 0,
        reportSha256: key,
        stdoutSha256: key,
        stderrSha256: key,
        catalogSha256: key,
        executableSha256: key,
        compilerMessagesSha256: key,
        sourceSha256: createHash("sha256").update(proposal.changes[1].newContent).digest("hex"),
        recipeSha256: key,
    };

    const evidence = {
        repository: proposal.repository,
        branch: proposal.branch,
        baseSha: sha,
        proposalSha256: proposalDigest(proposal),
        verifierRevision: request.verification.verifierRevision,
        runId: 123,
        runAttempt: 1,
        baseline: {
            ...result,
            exitCode: 101,
            failures: 1,
            assertionFailure: "assertion `left == right` failed",
            assertionFile: regression.path,
            assertionLine: 3,
            assertionSourceSha256: createHash("sha256").update(" assert_eq!(41,42);").digest("hex"),
        },
        patched: result,
        protectedPathsUnchanged: true,
        changedPaths: proposal.changes.map((change) => change.path),
        fileHashes: proposal.changes.map(({ path, sha256 }) => ({ path, sha256 })),
    };

    expect(parseVerificationEvidence(parsed, evidence).patched.exitCode).toBe(0);

    for (const change of [
        { proposalSha256: "d".repeat(64) },
        { verifierRevision: "d".repeat(40) },
        { baseline: { ...evidence.baseline, exitCode: 0 } },
        { patched: { ...result, tests: 2 } },
        { patched: { ...result, skipped: 1 } },
        { fileHashes: evidence.fileHashes.map((file) => ({ ...file, sha256: "d".repeat(64) })) },
    ])
        expect(() => parseVerificationEvidence(parsed, { ...evidence, ...change })).toThrow();
});

test("rejects injected commands, mismatched source, unsafe changes and oversized verification requests", () => {
    for (const verification of [
        { ...request.verification, command: "echo pass" },
        { ...request.verification, proposal: { ...proposal, baseSha: "d".repeat(40) } },
        { ...request.verification, proposal: { ...proposal, branch: "prerelease" } },
        { ...request.verification, regression: { ...regression, path: "tests/unit/other.rs" } },
        {
            ...request.verification,
            proposal: {
                ...proposal,
                changes: proposal.changes.map((change) => ({ ...change, path: "package.json" })),
            },
        },
        {
            ...request.verification,
            proposal: {
                ...proposal,
                changes: proposal.changes.map((change) => ({
                    ...change,
                    newContent: "é".repeat(32000),
                })),
            },
        },
    ])
        expect(() => parseStart({ ...request, verification })).toThrow();
    expect(() => parseStart({ ...request, runId: "9999999999999999999" })).toThrow();
});
