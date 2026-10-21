import { test, expect } from "bun:test";
import { gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { testAuditProofFixture } from "../../../tests/unit/fixtures/test-audit-proof.mjs";
import { Session } from "@opencode/schema/session";
import {
    createCodingActions,
    pollCodingVerification,
    type CodingState,
} from "../src/tools";
import { createRequiredSkillsPlugin } from "../src/skills";
import { auditFixture } from "./test-audit.test";
import { testAuditSchema } from "../../cloud-ci/src/test-audit-contract";
import { parseCodingRequest } from "../src/request";

test("existing-test tools start only a separate bounded audit and cannot export before receipt admission", async () => {
    const { request: raw, proposal: rawProposal } = auditFixture();
    const proposal = testAuditSchema.shape.proposal.parse(rawProposal);
    const compact = {
        purpose: "existing-test-strengthening" as const,
        assertion: { line: 4, source: "    assert_eq!(value, 1);" },
        fault: {
            path: "src/value.rs",
            oldQuote: "VALUE: u32 = 1",
            replacement: "VALUE: u32 = 2",
        },
    };
    const request = parseCodingRequest(raw);
    const skills = await createRequiredSkillsPlugin();
    const sessionID = Session.ID.create();
    skills.contextHook({ sessionID, system: [] });
    const context = { sessionID, signal: new AbortController().signal };
    let state: CodingState = { calls: 0, reads: [], verifiedDigests: [] };
    const calls: { url: string; body: unknown }[] = [];
    const proof = testAuditProofFixture();
    let terminal = false;
    const actions = createCodingActions({
        getRequest: async () => request,
        skills,
        update: async (change) => (state = change(state)),
        env: {
            CI_API_TOKEN: "x".repeat(32),
            CI_IMAGE_DIGEST: `sha256:${"c".repeat(64)}`,
            CI_VERIFIER_REVISION: "d".repeat(40),
            CI_SERVICE: {
                fetch: async (input, init) => {
                    if (!init?.body) {
                        const url = new URL(String(input));
                        if (url.pathname.endsWith("/receipt"))
                            return Response.json(proof.receipt);
                        if (
                            url.pathname.includes("/reports/") ||
                            url.pathname.includes("/logs/")
                        ) {
                            const [, , id, kind, name] =
                                url.pathname.split("/");
                            return proof.load(`${kind}/${id}/${name}`);
                        }
                        return Response.json({
                            id: proof.id,
                            sha: request.sha,
                            status: terminal ? "complete" : "running",
                        });
                    }
                    const body = JSON.parse(String(init.body));
                    calls.push({ url: String(input), body });
                    return Response.json({ id: proof.id, sha: request.sha });
                },
            },
        },
    });
    await expect(
        actions.propose_test_strengthening.execute(compact, context),
    ).rejects.toThrow("Read");
    for (const path of ["tests/value.rs", "src/value.rs"])
        await actions.read_source.execute(
            { path, start: 1, lines: 80 },
            context,
        );
    await actions.propose_test_strengthening.execute(compact, context);
    const digest = state.testAudit!.proposalSha256;
    await expect(
        actions.export_proposal.execute({ proposalSha256: digest }, context),
    ).rejects.toThrow("verified");
    await actions.verify_patch.execute({ proposalSha256: digest }, context);
    expect(calls).toHaveLength(1);
    expect(calls[0].body).toEqual({
        repository: request.repository,
        sha: request.sha,
        ref: "refs/heads/main",
        runId: "42",
        attempt: "1",
        testAudit: { proposal, verifierRevision: "d".repeat(40) },
    });
    expect(state.proposal).toBeUndefined();
    expect(state.verificationJob?.status).toBe("pending");
    terminal = true;
    const env = {
        CI_API_TOKEN: "x".repeat(32),
        CI_IMAGE_DIGEST: proof.policy.imageDigest,
        CI_VERIFIER_REVISION: proof.policy.verifierRevision,
        CI_SERVICE: {
            fetch: async (input: RequestInfo | URL) => {
                const url = new URL(String(input));
                if (url.pathname.endsWith("/receipt"))
                    return Response.json(proof.receipt);
                if (
                    url.pathname.includes("/reports/") ||
                    url.pathname.includes("/logs/")
                ) {
                    const [, , id, kind, name] = url.pathname.split("/");
                    return proof.load(`${kind}/${id}/${name}`);
                }
                return Response.json({
                    id: proof.id,
                    sha: request.sha,
                    status: "complete",
                });
            },
        },
    };
    await pollCodingVerification(
        {
            getRequest: async () => request,
            env,
            update: async (change) => (state = change(state)),
        },
        context.signal,
    );
    expect(state.verificationJob?.status).toBe("verified");
    const exported = JSON.parse(
        (
            await actions.export_proposal.execute(
                { proposalSha256: digest },
                context,
            )
        ).content,
    );
    expect(exported.testAuditHandover.changes).toHaveLength(1);
    expect(JSON.stringify(exported.testAuditHandover)).not.toContain("fault");
});

test("existing-test tool rejects an in-boundary fault without starting CI", async () => {
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
    const skills = await createRequiredSkillsPlugin();
    const sessionID = Session.ID.create();
    skills.contextHook({ sessionID, system: [] });
    const context = { sessionID, signal: new AbortController().signal };
    let state: CodingState = { calls: 0, reads: [], verifiedDigests: [] };
    const calls: unknown[] = [];
    const actions = createCodingActions({
        getRequest: async () => request,
        skills,
        update: async (change) => (state = change(state)),
        env: {
            CI_API_TOKEN: "x".repeat(32),
            CI_IMAGE_DIGEST: `sha256:${"c".repeat(64)}`,
            CI_VERIFIER_REVISION: "d".repeat(40),
            CI_SERVICE: {
                fetch: async (input, init) => {
                    calls.push({ input: String(input), init });
                    return Response.json({ id: "unexpected", sha: request.sha });
                },
            },
        },
    });
    for (const path of ["tests/value.rs", "src/value.rs"])
        await actions.read_source.execute({ path, start: 1, lines: 80 }, context);
    await expect(
        actions.propose_test_strengthening.execute(
            {
                purpose: "existing-test-sensitivity",
                assertion: { line: 4 },
                fault: {
                    path: "src/value.rs",
                    oldQuote: "assert_eq!(super::VALUE, 1);",
                    replacement: "assert_eq!(super::VALUE, 2);",
                },
            },
            context,
        ),
    ).rejects.toThrow("Automatic repairs cannot change existing Rust tests");
    expect(calls).toHaveLength(0);
});
