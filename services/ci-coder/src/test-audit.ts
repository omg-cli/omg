import { z } from "zod";
import { createHash } from "node:crypto";
import {
    testAuditSchema,
    testAuditDigest,
} from "../../cloud-ci/src/test-audit-contract";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { assertRustSourceChange } from "../../../scripts/rust-source-policy.mjs";
import type { CodingRequest } from "./request";

export function createTestAuditProposal(
    request: CodingRequest,
    input: unknown,
) {
    const task = request.testAuditTask;
    if (!task) throw new Error("Existing-test audit task required");
    const { proposal } = testAuditSchema.parse({
        verifierRevision: "0".repeat(40),
        proposal: input,
    });
    if (
        proposal.repository !== request.repository ||
        proposal.branch !== request.branch ||
        proposal.baseSha !== request.sha ||
        proposal.test.path !== task.path ||
        proposal.test.target !== task.target ||
        proposal.test.testName !== task.testName ||
        proposal.test.originalBlobSha !== task.originalBlobSha
    )
        throw new Error("Existing-test task identity differs from proposal");
    for (const file of request.source.sourceFiles)
        if (gitBlobSha(file.content) !== file.blobSha)
            throw new Error("Supplied source Git blob differs");
    const originalTest = request.source.sourceFiles.find(
        (file) => file.path === proposal.test.path,
    );
    const originalFault = request.source.sourceFiles.find(
        (file) => file.path === proposal.fault.path,
    );
    if (
        !originalTest ||
        originalTest.blobSha !== proposal.test.originalBlobSha ||
        originalTest.content !== proposal.test.originalContent ||
        !originalFault ||
        originalFault.blobSha !== proposal.fault.originalBlobSha ||
        !originalFault.content.includes(proposal.fault.oldContentQuote) ||
        originalFault.content === proposal.fault.newContent
    )
        throw new Error(
            "Existing-test audit original source differs from supplied snapshot",
        );
    assertRustSourceChange(
        proposal.fault.path,
        originalFault.content,
        proposal.fault.newContent,
    );
    if (
        proposal.test.path === proposal.fault.path &&
        (proposal.test.target !== "lib" ||
            originalFault.content.split("\n").length !==
                proposal.fault.newContent.split("\n").length)
    )
        throw new Error(
            "Same-file fault must preserve test line positions and use the library target",
        );
    return {
        proposal,
        proposalSha256: testAuditDigest(proposal),
        handover:
            proposal.purpose === "existing-test-sensitivity"
                ? null
                : {
                      purpose: proposal.purpose,
                      repository: proposal.repository,
                      branch: proposal.branch,
                      baseSha: proposal.baseSha,
                      testName: proposal.test.testName,
                      ...(proposal.test.target
                          ? { target: proposal.test.target }
                          : {}),
                      changes: [
                          {
                              path: proposal.test.path,
                              originalBlobSha: proposal.test.originalBlobSha,
                              newContent: proposal.test.newContent,
                              sha256: proposal.test.sha256,
                          },
                      ],
                  },
    };
}
export type CoderTestAudit = ReturnType<typeof createTestAuditProposal>;

export const testAuditToolSchema = z.strictObject({
    purpose: z.enum([
        "existing-test-strengthening",
        "existing-test-sensitivity",
    ]),
    assertion: z.strictObject({
        line: z.number().int().positive().safe(),
        source: z
            .string()
            .min(1)
            .max(2000)
            .describe(
                "One physical assertion line, already rustfmt-stable; omit messages that would wrap; a rustfmt diff is setup failure, not proof",
            )
            .optional(),
    }),
    fault: z.strictObject({
        path: z.string().max(240),
        oldQuote: z.string().min(1).max(4000),
        replacement: z.string().max(4000),
    }),
});
export function buildTestAuditProposal(
    request: CodingRequest,
    raw: unknown,
): CoderTestAudit {
    const input = testAuditToolSchema.parse(raw),
        task = request.testAuditTask;
    if (!task) throw new Error("Existing-test audit task required");
    const test = request.source.sourceFiles.find(
        (file) => file.path === task.path,
    );
    const fault = request.source.sourceFiles.find(
        (file) => file.path === input.fault.path,
    );
    if (
        !test ||
        !fault ||
        fault.content.split(input.fault.oldQuote).length !== 2
    )
        throw new Error(
            "Fault replacement must match one exact supplied source quote",
        );
    const newline = test.content.includes("\r\n") ? "\r\n" : "\n";
    const lines = test.content.match(/[^\n]*\n|[^\n]+$/g) ?? [];
    if (input.assertion.line > lines.length)
        throw new Error("Audit assertion line outside supplied test");
    if (input.purpose === "existing-test-strengthening") {
        if (!input.assertion.source || /[\r\n]/.test(input.assertion.source))
            throw new Error("One assertion source line required");
        lines.splice(
            input.assertion.line - 1,
            0,
            input.assertion.source + newline,
        );
    } else if (input.assertion.source !== undefined)
        throw new Error(
            "Sensitivity uses the existing assertion without inserted source",
        );
    const newContent =
        input.purpose === "existing-test-strengthening"
            ? lines.join("")
            : test.content;
    const faultContent = fault.content.replace(
        input.fault.oldQuote,
        input.fault.replacement,
    );
    const hash = (value: string) =>
        createHash("sha256").update(value).digest("hex");
    return createTestAuditProposal(request, {
        purpose: input.purpose,
        repository: request.repository,
        branch: request.branch,
        baseSha: request.sha,
        test: {
            ...task,
            originalContent: test.content,
            newContent,
            sha256: hash(newContent),
            assertionLine: input.assertion.line,
        },
        fault: {
            path: fault.path,
            originalBlobSha: fault.blobSha,
            oldContentQuote: input.fault.oldQuote,
            newContent: faultContent,
            sha256: hash(faultContent),
        },
    });
}
