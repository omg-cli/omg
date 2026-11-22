import { randomUUID } from "node:crypto";
import { lstat, open, readFile, rename, rm } from "node:fs/promises";
import { basename } from "node:path";
import { parseArgs } from "node:util";
import { fileHash, scanArchive, type ArchiveState } from "../advisories/scripts/archive";
import { baselineBinding, operatorPost, proofProgress, readCheckpoint, verifyIngestReply, type BaselineBinding } from "../advisories/scripts/operator";
import { boundedBody, isGitHubInstallationToken, object } from "../advisories/src/domain";
import { CANONICAL_ORIGIN, STAGE_ORIGIN } from "./stage-identity";
import { stageCheckpoint, stageOperatorFetcher } from "./transport";

const digest = "1d6c61c44cf3e269b6d60ed2fe0a3aa1f7e55445c7f170f16f2fa063bbf73db3";
const size = 670607648;
const release_tag = "cve_2026-11-21_0000Z";
const asset = "2026-11-21_all_CVEs_at_midnight.zip.zip";
const commit = "0acf54247f05316804b369e2e2eb715f7e4ec71d";
const baseline_at = "2026-11-21T00:00:00.000Z";

async function run() {
    const { values, positionals } = parseArgs({ strict: true, allowPositionals: true,
        options: { state: { type: "string" }, archive: { type: "string" }, "max-records": { type: "string", default: "256" } } });
    const [operation] = positionals;
    const path = values.state;
    const max = Number(values["max-records"]);
    if (positionals.length !== 1 || !path || !Number.isSafeInteger(max) || max < 1 || max > 1000 ||
        (operation !== "ingest" && operation !== "finalize" && operation !== "prove"))
        throw new Error("expected ingest, finalize or prove with --state, and ingest with --archive and at most 1000 records");
    const endpoint = new URL(STAGE_ORIGIN);
    const fetcher = stageOperatorFetcher(process.env.STAGE_ACCESS_CLIENT_ID, process.env.STAGE_ACCESS_CLIENT_SECRET);
    const token = operation === "prove" ? process.env.STAGE_RUNTIME_REFRESH_SECRET : process.env.STAGE_INGEST_TOKEN;
    if (!token || token.length < 32) throw new Error("stage-only operation secret required");
    const post = (path: string, body: unknown) => operatorPost({ endpoint, token, path, body: JSON.stringify(body), fetcher });
    let state: ArchiveState = { digest, next_entry: 0, accepted: 0, exhausted: false, finished_at: null };
    let binding: BaselineBinding | undefined;
    try {
        const info = await lstat(path);
        if (!info.isFile() || info.isSymbolicLink() || info.size > 16384 || (info.mode & 0o077) !== 0)
            throw new Error("checkpoint must be a bounded private file");
        const saved = stageCheckpoint(JSON.parse(await readFile(path, "utf8")));
        binding = baselineBinding(saved.baseline, digest, CANONICAL_ORIGIN);
        state = readCheckpoint(saved, binding);
    } catch (error) {
        if (!(error instanceof Error && "code" in error && error.code === "ENOENT" && operation === "ingest")) throw error;
    }
    if (operation === "prove") {
        const githubToken = process.env.GITHUB_TOKEN;
        if (!state.exhausted || !binding || !isGitHubInstallationToken(githubToken)) throw new Error("exhausted stage session and ephemeral GitHub token required");
        for (let step = 1; step <= 20; step++) {
            const result = proofProgress(await post("/internal/baseline/verify", {
                ...binding, release_tag, asset, github_token: githubToken,
            }), { digest, release_tag, asset });
            if (result.commit_sha !== commit) throw new Error("publisher commit pin differs");
            console.log(JSON.stringify({ ...result, step }));
            if (result.phase === "verified" || result.phase === "awaiting_import" || result.phase === "awaiting_catchup") return;
        }
        return;
    }
    if (operation === "finalize") {
        if (!binding || !state.exhausted) throw new Error("stage archive is not exhausted");
        const result = await post("/internal/baseline", { ...binding, baseline_at, accepted: state.accepted, exhausted: true, finished_at: state.finished_at });
        console.log(JSON.stringify({ caught_up: result.caught_up === true, archive_verified: result.archive_verified === true }));
        return;
    }
    const archive = values.archive;
    if (!archive || basename(archive) !== asset || (await lstat(archive)).size !== size || await fileHash(archive) !== digest)
        throw new Error("bound stage archive bytes required");
    const publisher = "https://api.github.com/repos/CVEProject/cvelistV5";
    async function publisherMetadata(path: string) {
        const result = await fetch(publisher + path, { redirect: "error", signal: AbortSignal.timeout(15000),
            headers: { accept: "application/vnd.github+json", "user-agent": "omg-advisories-stage" } });
        if (!result.ok) throw new Error("publisher metadata unavailable");
        return object(JSON.parse(await boundedBody(result.body, 1024 * 1024)));
    }
    const [release, ref] = await Promise.all([publisherMetadata(`/releases/tags/${release_tag}`), publisherMetadata(`/git/ref/tags/${release_tag}`)]);
    const target = object(ref.object);
    if (target.type !== "commit" || target.sha !== commit || release.tag_name !== release_tag || !Array.isArray(release.assets) ||
        release.assets.map(object).filter(entry => entry.name === asset && entry.size === size && entry.digest === `sha256:${digest}`).length !== 1)
        throw new Error("publisher stage identity differs");
    const started = baselineBinding(await post("/internal/baseline/start", { digest, baseline_at, ...binding }), digest, CANONICAL_ORIGIN);
    if (binding && (started.instance_id !== binding.instance_id || started.session_id !== binding.session_id))
        throw new Error("stage resume session differs");
    const save = async (next: ArchiveState) => {
        const temp = `${path}.${randomUUID()}`;
        try {
            const file = await open(temp, "wx", 0o600);
            try { await file.writeFile(JSON.stringify({ transport_endpoint: STAGE_ORIGIN, checkpoint: { ...next, baseline: started } })); await file.sync(); }
            finally { await file.close(); }
            await rename(temp, path);
        } finally {
            await rm(temp, { force: true });
        }
        state = next;
    };
    await save(state);
    if (!state.exhausted) await scanArchive({ path: archive, digest, state, maxRecords: max, batchSize: 64,
        encodeBatch: (records) => JSON.stringify({ source: "cve", records, baseline: started }),
        send: async body => {
            const batch = object(JSON.parse(body));
            if (!Array.isArray(batch.records)) throw new Error("invalid stage batch");
            verifyIngestReply(await post("/internal/ingest", batch), batch.records.length);
        }, save });
    console.log(JSON.stringify({ accepted: state.accepted, next_entry: state.next_entry, exhausted: state.exhausted }));
}

run().catch(() => {
    console.error("Stage operation refused; inspect the private checkpoint and sanitized operator evidence");
    process.exitCode = 1;
});
