import { readFile, rename, stat, lstat, open, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { basename } from "node:path";
import { parseArgs } from "node:util";
import { scanArchive, fileHash, type ArchiveState } from "./archive";
import { boundedBody, object, string, date } from "../src/domain";
import { baselineBinding, operatorPost, readCheckpoint, recoverCheckpoint, verifyIngestReply, type BaselineBinding } from "./operator";
const { values } = parseArgs({
    options: {
        archive: { type: "string" },
        state: { type: "string" },
        endpoint: { type: "string" },
        "release-tag": { type: "string" },
        asset: { type: "string" },
        "token-file": { type: "string" },
        "max-records": { type: "string", default: "1000" },
        "delay-ms": { type: "string", default: "0" },
        "resume-instance": { type: "string" },
        "resume-session": { type: "string" },
        "dry-run": { type: "boolean", default: false },
        finalize: { type: "boolean", default: false },
        help: { type: "boolean", default: false },
    },
    strict: true,
});
if (values.help) {
    process.stdout.write(
        "bun run bootstrap --archive PATH --state PATH --release-tag TAG --asset NAME [--endpoint HTTPS_URL] [--token-file MODE_600_FILE] [--max-records 1000] [--delay-ms 0] [--resume-instance ID --resume-session UUID] [--dry-run] [--finalize]\nINGEST_TOKEN environment variable is supported. No Cloudflare account credential is needed. Dry run never writes HTTP. Recovery requires a missing state file and replays the exact bound archive/session from zero. Batches remain serial and bounded by service limits.\n",
    );
    process.exit(0);
}
async function run() {
    if (
        !values.archive ||
        !values.state ||
        !values["release-tag"] ||
        !values.asset
    )
        throw new Error("archive, state, release-tag and asset required");
    const max = Number(values["max-records"]);
    const delay = Number(values["delay-ms"]);
    if (
        !Number.isSafeInteger(max) ||
        max < 1 ||
        max > 100_000 ||
        !Number.isSafeInteger(delay) ||
        delay < 0 ||
        delay > 60_000
    )
        throw new Error("invalid operator bounds");
    const tag = values["release-tag"];
    if (!/^[a-zA-Z0-9_.-]{1,100}$/.test(tag))
        throw new Error("invalid release tag");
    const name = values.asset;
    const full =
        /^(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight\.zip(?:\.zip)?$/.exec(name);
    if (!full?.[1] || basename(values.archive) !== name)
        throw new Error("expected full baseline asset filename");
    const response = await fetch(
        `https://api.github.com/repos/CVEProject/cvelistV5/releases/tags/${encodeURIComponent(tag)}`,
        {
            redirect: "error",
            signal: AbortSignal.timeout(20_000),
            headers: {
                "User-Agent": "omg-advisories-bootstrap",
                Accept: "application/vnd.github+json",
            },
        },
    );
    if (!response.ok)
        throw new Error(`release metadata HTTP ${response.status}`);
    const release = object(
        JSON.parse(await boundedBody(response.body, 1024 * 1024)),
    );
    if (release.tag_name !== tag || !Array.isArray(release.assets))
        throw new Error("invalid release metadata");
    const asset = release.assets.map(object).find((v) => v.name === name);
    if (!asset) throw new Error("asset absent from official release");
    const digest = string(asset.digest).replace(/^sha256:/, "");
    if (!/^[a-f0-9]{64}$/.test(digest))
        throw new Error("official asset SHA-256 missing");
    if (
        (await stat(values.archive)).size !== asset.size ||
        (await fileHash(values.archive)) !== digest
    )
        throw new Error("official asset bytes mismatch");
    const baseline = date(`${full[1]}T00:00:00Z`);
    let token = process.env.INGEST_TOKEN;
    if (values["token-file"]) {
        const info = await stat(values["token-file"]);
        if ((info.mode & 0o077) !== 0)
            throw new Error("token file must be private");
        token = (await readFile(values["token-file"], "utf8")).trim();
    }
    const endpoint = values.endpoint ? new URL(values.endpoint) : null;
    if (
        !values["dry-run"] &&
        (!endpoint ||
            endpoint.protocol !== "https:" ||
            endpoint.username ||
            endpoint.password ||
            endpoint.search ||
            endpoint.hash ||
            endpoint.pathname !== "/" ||
            !token ||
            token.length < 32)
    )
        throw new Error("HTTPS endpoint and strong ingest token required");
    async function post(path: string, body: string) {
        if (values["dry-run"]) return {};
        if (!endpoint || !token)
            throw new Error("missing writer configuration");
        return operatorPost({endpoint,token,path,body});
    }
    let binding: BaselineBinding | null = null;
    let state: ArchiveState = {
        digest,
        next_entry: 0,
        accepted: 0,
        exhausted: false,
        finished_at: null,
    };
    let resumed=false;
    try {
        const info=await lstat(values.state);
        if(!info.isFile() || info.isSymbolicLink() || info.size>16*1024) throw new Error("resume state must be a bounded regular file");
        const saved = object(JSON.parse(await readFile(values.state, "utf8")));
        const savedBinding=object(saved.baseline);
        binding=baselineBinding(savedBinding,digest,endpoint?.origin??string(savedBinding.endpoint));
        state=readCheckpoint(saved,binding);
        resumed=true;
    } catch (error) {
        if (
            !(
                error instanceof Error &&
                "code" in error &&
                error.code === "ENOENT"
            )
        )
            throw error;
    }
    if(values["resume-instance"] || values["resume-session"]) {
        if(resumed || !endpoint || !values["resume-instance"] || !values["resume-session"]) throw new Error("recovery requires both instance/session, endpoint and a missing state file");
        binding=baselineBinding({digest,endpoint:endpoint.origin,instance_id:values["resume-instance"],session_id:values["resume-session"]},digest,endpoint.origin);
        state=recoverCheckpoint(binding);
    }
    const startAccepted=state.accepted;
    const startedAt=performance.now();
    let lastProgress=startedAt;
    async function save(next: ArchiveState) {
        if (values["dry-run"]) return;
        const path = values.state;
        if (!path) throw new Error("missing state path");
        const temporary=`${path}.tmp-${randomUUID()}`;
        try {
            const file=await open(temporary,"wx",0o600);
            try { await file.writeFile(JSON.stringify({...next,baseline:binding})+"\n"); await file.sync(); }
            finally { await file.close(); }
            await rename(temporary,path);
        } finally { await rm(temporary,{force:true}); }
        const now=performance.now();
        if(now-lastProgress>=5000 || next.exhausted) {
            process.stderr.write(JSON.stringify({event:"bootstrap_progress",wave_records:next.accepted-startAccepted,accepted:next.accepted,next_entry:next.next_entry,exhausted:next.exhausted,elapsed_seconds:Math.round((now-startedAt)/1000)})+"\n");
            lastProgress=now;
        }
    }
    if (!values["dry-run"]) {
        const started = await post("/internal/baseline/start", JSON.stringify({
            digest,
            baseline_at: baseline,
            ...binding,
        }));
        const actual=baselineBinding(started,digest,endpoint?.origin??"");
        if(binding && (actual.instance_id!==binding.instance_id || actual.session_id!==binding.session_id)) throw new Error("baseline response changed the requested session binding");
        binding=actual;
        await save(state);
    }
    if (!state.exhausted)
        await scanArchive({
            path: values.archive,
            digest,
            state,
            maxRecords: max,
            batchSize: 64,
            encodeBatch: (records) => JSON.stringify({source: "cve", records, baseline: binding}),
            send: async (body) => {
                const reply=await post("/internal/ingest", body);
                if(!values["dry-run"]) {
                    const sent=object(JSON.parse(body)).records;
                    if(!Array.isArray(sent)) throw new Error("invalid encoded ingest records");
                    verifyIngestReply(reply,sent.length);
                    if(delay>0) await Bun.sleep(delay);
                }
            },
            save,
        });
    let finalized: Record<string,unknown> | undefined;
    if (values.finalize) {
        if (!state.exhausted) throw new Error("archive not exhausted");
        finalized = await post("/internal/baseline", JSON.stringify({
            ...binding,
            digest,
            baseline_at: baseline,
            accepted: state.accepted,
            exhausted: true,
            finished_at: state.finished_at,
        }));
    }
    process.stdout.write(
        JSON.stringify({
            dry_run: values["dry-run"],
            accepted: state.accepted,
            exhausted: state.exhausted,
            bootstrap_complete: finalized?.bootstrap_complete === true,
            archive_verified: finalized?.archive_verified === true,
            caught_up: finalized?.caught_up === true,
            next_entry: state.next_entry,
            wave_records:state.accepted-startAccepted,
            elapsed_seconds:Math.round((performance.now()-startedAt)/1000),
        }) + "\n",
    );
}
run().catch((error) => {
    process.stderr.write(
        `${error instanceof Error ? error.message : "bootstrap failed"}\n`,
    );
    process.exitCode = 1;
});
