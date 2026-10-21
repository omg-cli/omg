import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { Schema } from "effect";

export const artifactsRemote =
    "https://f1e95b3e1b502cf366dfc81a863695fa.artifacts.cloudflare.net/git/omg-ci/omg.git";

const commitSha = Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/));
const credential = Schema.String.check(Schema.isPattern(/^[^\r\n]{32,}$/));

export function parseSourceToken(value) {
    return Schema.decodeUnknownSync(
        Schema.Struct({
            repository: Schema.Literal("omg-cli/omg"),
            token: credential,
            id: Schema.String.check(Schema.isMinLength(1)),
            expiresAt: Schema.String.check(Schema.isPattern(/^\d{4}-\d{2}-\d{2}T/)),
        }),
    )(value);
}

export function mirrorRequest(sha, token) {
    if (!Schema.is(commitSha)(sha)) throw new Error("CI source must be an exact commit SHA.");

    if (!Schema.is(credential)(token))
        throw new Error("An Artifacts repository credential is required.");

    return {
        args: ["push", artifactsRemote, `${sha}:refs/heads/ci/${sha}`],
        env: {
            PATH: process.env.PATH,
            SystemRoot: process.env.SystemRoot,
            HOME: process.env.HOME,
            USERPROFILE: process.env.USERPROFILE,
            GIT_TERMINAL_PROMPT: "0",
            GIT_CONFIG_NOSYSTEM: "1",
            GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
            GIT_CONFIG_COUNT: "1",
            GIT_CONFIG_KEY_0: "http.extraHeader",
            GIT_CONFIG_VALUE_0: `Authorization: Bearer ${token}`,
        },
        ref: `refs/heads/ci/${sha}`,
    };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
    const sha = process.argv[2];

    const config = JSON.parse(
        await readFile(path.join(homedir(), "ci", "omg-cloud-ci.json"), "utf8"),
    );

    if (config.endpoint !== "https://omg-cloud-ci.latham.workers.dev/")
        throw new Error("Source credentials require the dedicated CI Worker.");

    const ownerToken = (await readFile(config.tokenFile, "utf8")).trim();

    if (!Schema.is(credential)(ownerToken)) throw new Error("Invalid CI credential.");

    const response = await fetch(new URL("/source-token", config.endpoint), {
        method: "POST",
        headers: { Authorization: `Bearer ${ownerToken}`, "Content-Type": "application/json" },
        body: "{}",
        redirect: "error",
        signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) throw new Error(`Source credential request failed: HTTP ${response.status}.`);

    const { token } = parseSourceToken(await response.json());
    const request = mirrorRequest(sha, token);
    const git = promisify(execFile);

    const actual = (
        await git("git", ["rev-parse", "--verify", `${sha}^{commit}`], {
            timeout: 30000,
            windowsHide: true,
        })
    ).stdout.trim();

    if (actual !== sha) throw new Error("CI source must be an exact existing commit.");
    await git("git", request.args, {
        env: request.env,
        timeout: 180000,
        maxBuffer: 1024 * 1024,
        windowsHide: true,
    });

    const result = await git("git", ["ls-remote", artifactsRemote, request.ref], {
        env: request.env,
        timeout: 30000,
        windowsHide: true,
    });

    if (result.stdout.trim() !== `${sha}\t${request.ref}`)
        throw new Error("Artifacts did not acknowledge the exact source commit.");
    process.stdout.write(`${JSON.stringify({ sha, ref: request.ref, remote: artifactsRemote })}\n`);
}
