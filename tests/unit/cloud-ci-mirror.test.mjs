import { describe, expect, test } from "bun:test";
import {
    artifactsRemote,
    mirrorRequest,
    parseSourceToken,
} from "../../scripts/cloud-ci-mirror.mjs";

describe("Cloudflare CI source mirror", () => {
    test("rejects a credential issued for another repository", () => {
        expect(() =>
            parseSourceToken({
                repository: "other/repo",
                token: "t".repeat(40),
                id: "token-id",
                expiresAt: "2026-10-20T18:00:00Z",
            }),
        ).toThrow();
    });
    test("rejects revisions and Git option injection before invoking Git", () => {
        for (const sha of ["main", "--all", "a".repeat(39), "A".repeat(40), "a".repeat(40) + "\n"])
            expect(() => mirrorRequest(sha, "t".repeat(40))).toThrow("exact commit");
    });

    test("binds one immutable source ref without putting a credential in arguments", () => {
        const sha = "a".repeat(40);
        const token = "secret-".repeat(8);
        const request = mirrorRequest(sha, token);
        expect(request.args).toEqual(["push", artifactsRemote, `${sha}:refs/heads/ci/${sha}`]);
        expect(JSON.stringify(request.args)).not.toContain(token);
        expect(request.env.GIT_CONFIG_VALUE_0).toBe(`Authorization: Bearer ${token}`);
        expect(request.env.GH_TOKEN).toBeUndefined();
        expect(request.env.GITHUB_TOKEN).toBeUndefined();
        expect(request.env.GIT_TERMINAL_PROMPT).toBe("0");
    });

    test("rejects absent credentials and header injection", () => {
        for (const token of [undefined, "short", "x".repeat(40) + "\r\nInjected: true"])
            expect(() => mirrorRequest("a".repeat(40), token)).toThrow("credential");
    });
});
