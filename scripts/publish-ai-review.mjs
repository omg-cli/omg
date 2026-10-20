import { Schema } from "effect";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import { publishAiReview } from "./ai-review-publication.mjs";

const command = promisify(execFile);

export function createGhClient() {
    if (!process.env.GH_TOKEN)
        throw new Error("A job-scoped GH_TOKEN is required; owner CLI credentials are not used.");

    return {
        async request(method, route, body) {
            if (!route.startsWith("/repos/omg-cli/omg/") || !["GET", "POST"].includes(method))
                throw new Error("Unexpected GitHub publication request.");
            const args = [
                "api",
                "--hostname",
                "github.com",
                "--include",
                "--method",
                method,
                route,
            ];

            if (body) args.push("--input", "-");
            let output;

            try {
                const pending = command("gh", args, {
                    timeout: 30000,
                    maxBuffer: 4 * 1024 * 1024,
                    windowsHide: true,
                });

                pending.child.stdin.end(body ? JSON.stringify(body) : undefined);
                output = (await pending).stdout;
            } catch (error) {
                if (
                    method === "GET" &&
                    route.includes("/git/ref/heads/ai-fix/") &&
                    Schema.is(Schema.String)(error.stdout) &&
                    /^HTTP\/\S+\s+404\b/.test(error.stdout)
                )
                    return null;
                throw new Error("GitHub publication request failed.");
            }

            const separator = output.search(/\r?\n\r?\n/);

            if (separator < 0)
                throw new Error("GitHub response did not contain an API status header.");

            return JSON.parse(output.slice(separator).trim());
        },
    };
}

export async function main(args = process.argv.slice(2)) {
    const publish = args.includes("--publish");
    const files = args.filter((argument) => argument !== "--publish");

    if (
        files.length !== 3 ||
        args.filter((argument) => argument === "--publish").length > 1 ||
        files.some((argument) => argument.startsWith("--"))
    )
        throw new Error(
            "Usage: bun scripts/publish-ai-review.mjs <proposal.json> <receipt.json> <trusted-policy.json> [--publish]",
        );

    const documents = await Promise.all(
        files.map(async (file) => {
            const bytes = await readFile(file);

            if (bytes.byteLength > 256 * 1024)
                throw new Error("Publication input exceeds its byte budget.");

            return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        }),
    );

    const result = await publishAiReview({
        proposal: documents[0],
        receipt: documents[1],
        verifierRevision: documents[2].verifierRevision,
        requiredChecks: documents[2].requiredChecks,
        github: createGhClient(),
        publish,
    });

    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
}

if (import.meta.main) await main();
