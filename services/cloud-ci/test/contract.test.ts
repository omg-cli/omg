import { describe, expect, test } from "bun:test";
import { parseStart, nativeParams, receiptKey, terminalSuccess } from "../src/contract";

const input = {
    repository: "omg-cli/omg",
    sha: "a".repeat(40),
    ref: "refs/heads/main",
    runId: "123",
    attempt: "1",
};

describe("trusted CI request boundary", () => {
    test("preserves the immutable original source range without accepting Git expressions", () => {
        const sourceBaseSha = "b".repeat(40);

        expect(parseStart({ ...input, sourceBaseSha })).toMatchObject({ sourceBaseSha });
        expect(() => parseStart({ ...input, sourceBaseSha: "HEAD^" })).toThrow();
    });
    test("binds the exact source commit and GitHub attempt", () => {
        const request = parseStart(input);
        expect(nativeParams(request)).toMatchObject({
            provider: "cloudflare-artifacts",
            owner: "omg-ci",
            repo: "omg",
            sha: input.sha,
            providerData: { namespace: "omg-ci" },
        });
        expect(receiptKey(request)).toBe(`receipts/123-1/${input.sha}.json`);
        expect(receiptKey(parseStart({ ...input, attempt: "2" }))).not.toBe(receiptKey(request));
    });
    test("refuses alternate repositories, commands, short hashes and unsafe refs", () => {
        for (const change of [
            { repository: "other/repo" },
            { sha: "abc" },
            { command: "echo pass" },
            { ref: "main;echo bad" },
            { runId: "../123" },
            { ref: "refs/heads/other" },
        ]) {
            expect(() => parseStart({ ...input, ...change })).toThrow();
        }
    });
    test("never admits incomplete or failed workflows as successful", () => {
        for (const status of [
            "queued",
            "running",
            "errored",
            "terminated",
            "unknown",
            "waiting",
            "paused",
        ])
            expect(terminalSuccess(status)).toBe(false);
        expect(terminalSuccess("complete")).toBe(true);
    });
});
