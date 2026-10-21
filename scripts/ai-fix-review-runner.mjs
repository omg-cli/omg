import { readFile, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { createGhClient } from "./publish-ai-review.mjs";
import { reviewAiFix } from "./ai-fix-review.mjs";
import { admitQemuArtifacts } from "./ai-fix-review-qemu.mjs";

const command = promisify(execFile);
const ci = "https://omg-cloud-ci.latham.workers.dev";
const inspector = "https://omg-ci-inspector.latham.workers.dev";

async function service(url, token, body) {
    if (!/^[^\s]{32,512}$/.test(token ?? "")) throw new Error("Dedicated review service credential missing.");
    const response = await fetch(url, { method: body ? "POST" : "GET", redirect: "error",
        headers: { authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}) },
        ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(body ? 120000 : 30000) });
    if (!response.ok) throw new Error(`Trusted review service returned HTTP ${response.status}.`);
    return response;
}

async function json(response) {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Review service response missing.");
    const chunks = [];
    let size = 0;
    for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > 2 * 1024 * 1024) {
            await reader.cancel();
            throw new Error("Review service response exceeds the bounded evidence limit.");
        }
        chunks.push(chunk.value);
    }
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks)));
}

export async function main() {
    const { GITHUB_SHA: revision, GITHUB_REPOSITORY: repository, GITHUB_RUN_ID: runId,
        GITHUB_RUN_ATTEMPT: attempt, OMG_CI_CONTROLLER_SHA: controllerRevision,
        OMG_CI_API_TOKEN: ciToken, OMG_CI_INSPECTOR_TOKEN: inspectorToken } = process.env;
    if (repository !== "omg-cli/omg" || !/^[a-f0-9]{40}$/.test(revision ?? "") ||
        !/^[a-f0-9]{40}$/.test(controllerRevision ?? "") || !/^[1-9][0-9]*$/.test(runId ?? "") ||
        !/^[1-9][0-9]*$/.test(attempt ?? "")) throw new Error("Trusted review workflow identity required.");
    const { stdout } = await command("git", ["rev-parse", "HEAD"], { encoding: "utf-8", windowsHide: true });
    if (stdout.trim() !== revision) throw new Error("Review controller checkout is not this default-branch workflow commit.");
    const github = createGhClient();
    const main = await github.request("GET", "/repos/omg-cli/omg/git/ref/heads/main");
    if (main.object.sha !== revision) throw new Error("Review controller is no longer current main.");
    const event = JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH, "utf8"));
    let candidates;
    if (process.env.GITHUB_EVENT_NAME === "workflow_dispatch") {
        const number = Number(event.inputs?.pull_number);
        if (!Number.isSafeInteger(number) || number < 1) throw new Error("A valid fix PR number is required.");
        const pull = await github.request("GET", `/repos/omg-cli/omg/pulls/${number}`);
        candidates = [{ number, head: { sha: pull.head.sha } }];
    } else if (process.env.GITHUB_EVENT_NAME === "workflow_run") {
        const run = event.workflow_run;
        if (run?.repository?.full_name !== repository || run.conclusion !== "success" ||
            run.event !== "pull_request" || !/^[a-f0-9]{40}$/.test(run.head_sha ?? "") ||
            ![".github/workflows/ci.yml", ".github/workflows/coverage.yml", ".github/workflows/ci-orchestration.yml"].includes(run.path))
            throw new Error("Unexpected triggering verification workflow.");
        candidates = await github.request("GET", `/repos/omg-cli/omg/commits/${run.head_sha}/pulls?per_page=100`);
        if (!Array.isArray(candidates) || candidates.length >= 100) throw new Error("Ambiguous PR lookup.");
        candidates = candidates.filter((pull) => pull.head?.sha === run.head_sha && pull.state === "open");
    } else throw new Error("Only default-branch dispatch and completed verification workflows are admitted.");
    const results = [];
    candidates = candidates.filter((pull) => !pull.user || pull.user.id === 345568822);
    if (candidates.length > 1) throw new Error("One exact published fix PR per independent review is required.");
    for (const pull of candidates) {
        if (pull.user && pull.user.id !== 345568822) continue;
        const services = {
            ciJson: async (route) => json(await service(`${ci}${route}`, ciToken)),
            ciRaw: (route) => service(`${ci}${route}`, ciToken),
            inspectPatch: async (input) => json(await service(`${inspector}/patch-review`, inspectorToken, input)),
            admitQemu: admitQemuArtifacts,
            saveReview: async (record) => {
                const envelope = { repository, runId, attempt, report: { repository, branch: "main",
                    sha: revision, purpose: "independent-fix-review", patchReview: record } };
                await json(await service(`${ci}/review-records/${runId}-${attempt}`, ciToken, envelope));
                await writeFile(path.join(process.env.RUNNER_TEMP, "ai-fix-review.json"), `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
            },
        };
        results.push(await reviewAiFix({ github, services, number: pull.number, expectedHead: pull.head.sha,
            publisher: { login: process.env.OMG_CI_PUBLISHER_LOGIN, id: Number(process.env.OMG_CI_PUBLISHER_ID) },
            policy: { endpoint: `${ci}/`, imageDigest: process.env.OMG_CI_IMAGE_DIGEST,
                verifierRevision: process.env.OMG_CI_VERIFIER_REVISION, controllerRevision, reviewControllerRevision: revision },
            approve: process.argv.includes("--approve") }));
    }
    process.stdout.write(`${JSON.stringify({ results })}\n`);
}

if (import.meta.main) await main();
