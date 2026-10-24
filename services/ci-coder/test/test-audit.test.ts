import type { TestAudit } from "../../cloud-ci/src/test-audit-contract";
import { test, expect } from "bun:test";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { sha256 } from "../../../scripts/ai-review-publication.mjs";
import { createTestAuditProposal } from "../src/test-audit";
import { parseCodingRequest, operationIdentity } from "../src/request";

export function auditFixture() {
    const oldTest =
        "#[test]\nfn checks_value() {\n    let value = 1;\n    assert!(value > 0);\n}\n";
    const source = "pub const VALUE: u32 = 1;\n";
    const stronger = oldTest.replace(
        "    assert!(value > 0);",
        "    assert_eq!(value, 1);\n    assert!(value > 0);",
    );
    const request = {
        repository: "omg-cli/omg",
        branch: "main",
        sha: "a".repeat(40),
        runId: "42",
        attempt: "1",
        source: {
            repository: "omg-cli/omg",
            branch: "main",
            sha: "a".repeat(40),
            changedPaths: [],
            auditPaths: ["tests/value.rs", "src/value.rs"],
            diff: "",
            ciFailures: [],
            sourceFiles: [
                {
                    path: "tests/value.rs",
                    blobSha: gitBlobSha(oldTest),
                    content: oldTest,
                },
                {
                    path: "src/value.rs",
                    blobSha: gitBlobSha(source),
                    content: source,
                },
            ],
        },
        testAuditTask: {
            path: "tests/value.rs",
            testName: "checks_value",
            originalBlobSha: gitBlobSha(oldTest),
        },
    };
    const proposal: TestAudit["proposal"] = {
        purpose: "existing-test-strengthening",
        repository: "omg-cli/omg",
        branch: "main",
        baseSha: request.sha,
        test: {
            path: "tests/value.rs",
            testName: "checks_value",
            originalBlobSha: gitBlobSha(oldTest),
            originalContent: oldTest,
            newContent: stronger,
            sha256: sha256(stronger),
            assertionLine: 4,
        },
        fault: {
            path: "src/value.rs",
            originalBlobSha: gitBlobSha(source),
            oldContentQuote: "VALUE: u32 = 1",
            newContent: source.replace("= 1", "= 2"),
            sha256: sha256(source.replace("= 1", "= 2")),
        },
    };
    return { request, proposal };
}

test("existing-test coder binds task and both original blobs, exports only strengthened test", () => {
    const { request, proposal } = auditFixture();
    const parsed = parseCodingRequest(request);
    const result = createTestAuditProposal(parsed, proposal);
    if (!result.handover) throw new Error("Strengthening handover missing");
    expect(result.handover.changes).toEqual([
        {
            path: proposal.test.path,
            originalBlobSha: proposal.test.originalBlobSha,
            newContent: proposal.test.newContent,
            sha256: proposal.test.sha256,
        },
    ]);
    expect(JSON.stringify(result.handover)).not.toContain("fault");
    expect(operationIdentity(parsed)).not.toBe(
        operationIdentity(
            parseCodingRequest({ ...request, testAuditTask: undefined }),
        ),
    );
});

test("existing-test coder rejects substituted task, source, old bytes and mixed repair hypothesis", () => {
    const { request, proposal } = auditFixture();
    for (const forged of [
        { ...proposal, test: { ...proposal.test, testName: "other" } },
        {
            ...proposal,
            fault: { ...proposal.fault, originalBlobSha: "b".repeat(40) },
        },
        { ...proposal, test: { ...proposal.test, originalContent: "forged" } },
    ])
        expect(() =>
            createTestAuditProposal(parseCodingRequest(request), forged),
        ).toThrow();
    expect(() =>
        parseCodingRequest({ ...request, candidateIndex: 0 }),
    ).toThrow();
    expect(() =>
        parseCodingRequest({
            ...request,
            testAuditTask: {
                ...request.testAuditTask,
                originalBlobSha: "c".repeat(40),
            },
        }),
    ).toThrow();
});
import { buildTestAuditProposal } from "../src/test-audit";
test("compact model proposal reconstructs exact test/fault bytes and hashes without model file copies", () => {
    const { request, proposal } = auditFixture();
    const input = {
        purpose: "existing-test-strengthening",
        assertion: { line: 4, source: "    assert_eq!(value, 1);" },
        fault: {
            path: "src/value.rs",
            oldQuote: "VALUE: u32 = 1",
            replacement: "VALUE: u32 = 2",
        },
    };
    const built = buildTestAuditProposal(parseCodingRequest(request), input);
    expect(built.proposal).toEqual(proposal);
    expect(() =>
        buildTestAuditProposal(parseCodingRequest(request), {
            ...input,
            fault: { ...input.fault, oldQuote: "not present" },
        }),
    ).toThrow();
    expect(() =>
        buildTestAuditProposal(parseCodingRequest(request), {
            ...input,
            assertion: { line: 4, source: "return;" },
        }),
    ).toThrow();
});

test("sensitivity compact audit exports no patch and larger source remains audit-only", () => {
    const { request } = auditFixture();
    const result = buildTestAuditProposal(parseCodingRequest(request), {
        purpose: "existing-test-sensitivity",
        assertion: { line: 4 },
        fault: {
            path: "src/value.rs",
            oldQuote: "VALUE: u32 = 1",
            replacement: "VALUE: u32 = 2",
        },
    });
    expect(result.handover).toBeNull();
    expect(result.proposal.test.newContent).toBe(
        result.proposal.test.originalContent,
    );
    const large =
        "// bounded context\n".repeat(1800) +
        request.source.sourceFiles[0].content;
    const widened = {
        ...request,
        source: {
            ...request.source,
            sourceFiles: [
                {
                    ...request.source.sourceFiles[0],
                    content: large,
                    blobSha: gitBlobSha(large),
                },
                request.source.sourceFiles[1],
            ],
        },
        testAuditTask: {
            ...request.testAuditTask,
            originalBlobSha: gitBlobSha(large),
        },
    };
    expect(() => parseCodingRequest(widened)).not.toThrow();
    expect(() =>
        parseCodingRequest({ ...widened, testAuditTask: undefined }),
    ).toThrow();
});

test("compact audit admits a before-boundary production fault and rejects an in-boundary fault", () => {
    const { request: raw } = auditFixture();
    const source = "pub const VALUE: u32 = 1;\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn checks_value() {\n        assert_eq!(super::VALUE, 1);\n    }\n}\n";
    const request = parseCodingRequest({
        ...raw,
        source: {
            ...raw.source,
            sourceFiles: raw.source.sourceFiles.map((file) =>
                file.path === "src/value.rs"
                    ? { ...file, content: source, blobSha: gitBlobSha(source) }
                    : file,
            ),
        },
    });
    expect(
        buildTestAuditProposal(request, {
            purpose: "existing-test-sensitivity",
            assertion: { line: 4 },
            fault: {
                path: "src/value.rs",
                oldQuote: "VALUE: u32 = 1",
                replacement: "VALUE: u32 = 2",
            },
        }).proposal.fault.newContent,
    ).toContain("VALUE: u32 = 2");
    expect(() =>
        buildTestAuditProposal(request, {
            purpose: "existing-test-sensitivity",
            assertion: { line: 4 },
            fault: {
                path: "src/value.rs",
                oldQuote: "assert_eq!(super::VALUE, 1);",
                replacement: "assert_eq!(super::VALUE, 2);",
            },
        }),
    ).toThrow("Automatic repairs cannot change existing Rust tests");
});

function sameFileAuditRequest(content: string) {
    const { request } = auditFixture();
    return parseCodingRequest({
        ...request,
        source: {
            ...request.source,
            sourceFiles: [
                request.source.sourceFiles[0],
                {
                    path: "src/value.rs",
                    blobSha: gitBlobSha(content),
                    content,
                },
            ],
        },
        testAuditTask: {
            path: "src/value.rs",
            target: "lib",
            testName: "checks_value",
            originalBlobSha: gitBlobSha(content),
        },
    });
}

test("same-file audit faults preserve line positions outside cfg(test), including CRLF", () => {
    const content =
        "pub const VALUE: u32 = 1;\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn checks_value() {\n        assert_eq!(super::VALUE, 1);\n    }\n}\n";
    const request = sameFileAuditRequest(content);
    const sensitivity = {
        purpose: "existing-test-sensitivity" as const,
        assertion: { line: 7 },
    };
    expect(() =>
        buildTestAuditProposal(request, {
            ...sensitivity,
            fault: {
                path: "src/value.rs",
                oldQuote: "pub const VALUE: u32 = 1;",
                replacement:
                    "pub const VALUE: u32 = 1;\npub const EXTRA: u32 = 2;",
            },
        }),
    ).toThrow(
        "Same-file fault must preserve test line positions and use the library target",
    );
    expect(
        buildTestAuditProposal(request, {
            ...sensitivity,
            fault: {
                path: "src/value.rs",
                oldQuote: "pub const VALUE: u32 = 1;",
                replacement: "pub const VALUE: u32 = 2;",
            },
        }).proposal.fault.newContent,
    ).toContain("VALUE: u32 = 2");
    const crlf = sameFileAuditRequest(content.replace(/\n/g, "\r\n"));
    expect(() =>
        buildTestAuditProposal(crlf, {
            ...sensitivity,
            fault: {
                path: "src/value.rs",
                oldQuote: "pub const VALUE: u32 = 1;",
                replacement:
                    "pub const VALUE: u32 = 1;\r\npub const EXTRA: u32 = 2;",
            },
        }),
    ).toThrow(
        "Same-file fault must preserve test line positions and use the library target",
    );
    expect(
        buildTestAuditProposal(crlf, {
            ...sensitivity,
            fault: {
                path: "src/value.rs",
                oldQuote: "pub const VALUE: u32 = 1;",
                replacement: "pub const VALUE: u32 = 2;",
            },
        }).proposal.fault.newContent,
    ).toContain("VALUE: u32 = 2");
});
