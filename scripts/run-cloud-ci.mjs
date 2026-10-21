import { readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";
import { setTimeout } from "node:timers/promises";
import {
    parseCloudCiRequest,
    verifyCloudCiReceipt,
    verifyCloudCiObjects,
    admitCloudCiRuntime,
} from "./cloud-ci-evidence.mjs";

const [sha, branch, runId, attempt, output] = process.argv.slice(2);

if (process.argv.length !== 7 || !output)
    throw new Error(
        "Usage: bun scripts/run-cloud-ci.mjs <sha> <main> <run-id> <attempt> <receipt.json>",
    );

const input = {
    repository: "omg-cli/omg",
    sha,
    ref: `refs/heads/${branch}`,
    runId,
    attempt,
};

if (process.env.SOURCE_BASE_SHA) input.sourceBaseSha = process.env.SOURCE_BASE_SHA;

const request = parseCloudCiRequest(input);

const config = JSON.parse(await readFile(path.join(homedir(), "ci/omg-cloud-ci.json"), "utf8"));

const endpoint = new URL(config.endpoint);

if (endpoint.href !== "https://omg-cloud-ci.latham.workers.dev/")
    throw new Error("Cloudflare CI endpoint must be the dedicated Worker.");

const token = (await readFile(config.tokenFile, "utf8")).trim();

if (token.length < 32 || /[\r\n]/.test(token)) throw new Error("Invalid CI credential.");

const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

const runtime = await fetch(new URL("/health", endpoint), {
    headers, redirect: "error", signal: AbortSignal.timeout(30000),
});
if (!runtime.ok) throw new Error(`Cloudflare CI preflight failed: HTTP ${runtime.status}.`);
admitCloudCiRuntime(await runtime.json());

const start = await fetch(new URL("/runs", endpoint), {
    method: "POST",
    headers,
    body: JSON.stringify(request),
    redirect: "error",
    signal: AbortSignal.timeout(30000),
});

if (start.status !== 202) throw new Error(`Cloudflare CI start failed: HTTP ${start.status}.`);

const expectedId = `cl-${runId}-${attempt}-${sha}`;
const started = await start.json();

if (started.id !== expectedId || started.sha !== sha)
    throw new Error("Cloudflare CI start identity mismatch.");

const deadline = Date.now() + 35 * 60 * 1000;
let previousStatus;

for (;;) {
    if (Date.now() >= deadline)
        throw new Error("Cloudflare CI did not finish before its deadline.");

    const response = await fetch(new URL(`/runs/${expectedId}`, endpoint), {
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(30000),
    });

    if (!response.ok) throw new Error(`Cloudflare CI status failed: HTTP ${response.status}.`);

    const state = await response.json();

    if (state.id !== expectedId || state.sha !== sha)
        throw new Error("Cloudflare CI status identity mismatch.");

    if (state.status !== previousStatus) {
        console.log(JSON.stringify({ id: expectedId, status: state.status }));
        previousStatus = state.status;
    }

    if (["errored", "terminated", "unknown"].includes(state.status))
        throw new Error(`Cloudflare CI ended ${state.status}; no passing proof exists.`);

    if (state.status === "complete") break;

    await setTimeout(5000);
}

const response = await fetch(new URL(`/runs/${expectedId}/receipt`, endpoint), {
    headers,
    redirect: "error",
    signal: AbortSignal.timeout(30000),
});

if (!response.ok) throw new Error(`Cloudflare CI proof unavailable: HTTP ${response.status}.`);

const receipt = verifyCloudCiReceipt(await response.json(), request, {
    imageDigest: config.imageDigest,
});

await verifyCloudCiObjects(receipt, (key) => {
    const [kind, , name] = key.split("/");

    return fetch(new URL(`/runs/${expectedId}/${kind}/${name}`, endpoint), {
        headers,
        redirect: "error",
        signal: AbortSignal.timeout(120000),
    });
});

await writeFile(output, JSON.stringify(receipt, null, 2));

console.log(
    JSON.stringify({ verifiedSha: sha, receiptFile: output, conclusion: receipt.conclusion }),
);
