import { readFile, writeFile, rename, stat } from "node:fs/promises";
import { basename } from "node:path";
import { parseArgs } from "node:util";
import { scanArchive, fileHash, type ArchiveState } from "./archive";
import { boundedBody, object, string, date } from "../src/domain";
const { values } = parseArgs({
    options: {
        archive: { type: "string" },
        state: { type: "string" },
        endpoint: { type: "string" },
        "release-tag": { type: "string" },
        asset: { type: "string" },
        "token-file": { type: "string" },
        "max-records": { type: "string", default: "1000" },
        "delay-ms": { type: "string", default: "1000" },
        "dry-run": { type: "boolean", default: false },
        finalize: { type: "boolean", default: false },
        help: { type: "boolean", default: false },
    },
    strict: true,
});
if (values.help) {
    process.stdout.write(
        "bun run bootstrap --archive PATH --state PATH --release-tag TAG --asset NAME [--endpoint HTTPS_URL] [--token-file MODE_600_FILE] [--max-records 1000] [--delay-ms 1000] [--dry-run] [--finalize]\nINGEST_TOKEN environment variable is supported. No Cloudflare account credential is needed. Dry run never writes HTTP.\n",
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
        for (let attempt = 0; attempt < 5; attempt++) {
            const reply = await fetch(new URL(path, endpoint), {
                method: "POST",
                redirect: "error",
                signal: AbortSignal.timeout(60_000),
                headers: {
                    authorization: `Bearer ${token}`,
                    "content-type": "application/json",
                },
                body,
            });
            if (reply.ok) return object(await reply.json());
            await reply.body?.cancel();
            if (
                ![409, 429, 500, 502, 503, 504].includes(reply.status) ||
                attempt === 4
            )
                throw new Error(
                    `ingest HTTP ${reply.status}; progress retained`,
                );
            await Bun.sleep(Math.min(30_000, 1000 * 2 ** attempt));
        }
    }
    let binding: Record<string, unknown> | null = null;
    let state: ArchiveState = {
        digest,
        next_entry: 0,
        accepted: 0,
        exhausted: false,
        finished_at: null,
    };
    try {
        const saved = object(JSON.parse(await readFile(values.state, "utf8")));
        if (
            saved.digest !== digest ||
            !Number.isSafeInteger(saved.next_entry) ||
            !Number.isSafeInteger(saved.accepted) ||
            Number(saved.next_entry) < 0 || Number(saved.next_entry) > 1_000_000 ||
            Number(saved.accepted) < 0 || Number(saved.accepted) > 1_000_000 ||
            typeof saved.exhausted !== "boolean" ||
            (saved.exhausted && saved.accepted === 0) ||
            !(
                saved.finished_at === null ||
                typeof saved.finished_at === "string"
            )
        )
            throw new Error("invalid resume state");
        if (!values["dry-run"]) {
            binding = object(saved.baseline);
            if (binding.digest !== digest || binding.endpoint !== endpoint?.origin || typeof binding.instance_id !== "string" || typeof binding.session_id !== "string")
                throw new Error("invalid resume instance or endpoint binding");
        }
        state = {
            digest,
            next_entry: Number(saved.next_entry),
            accepted: Number(saved.accepted),
            exhausted: saved.exhausted,
            finished_at: saved.finished_at,
        };
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
    async function save(next: ArchiveState) {
        if (values["dry-run"]) return;
        const path = values.state;
        if (!path) throw new Error("missing state path");
        await writeFile(`${path}.tmp`, JSON.stringify({...next, baseline: binding}) + "\n", {
            mode: 0o600,
        });
        await rename(`${path}.tmp`, path);
    }
    if (!values["dry-run"]) {
        const started = await post("/internal/baseline/start", JSON.stringify({
            digest,
            baseline_at: baseline,
            ...binding,
        }));
        if (!started || started.digest !== digest || started.endpoint !== endpoint?.origin || typeof started.instance_id !== "string" || typeof started.session_id !== "string")
            throw new Error("invalid baseline session response");
        binding = {digest, endpoint:started.endpoint, instance_id:started.instance_id, session_id:started.session_id};
        await save(state);
    }
    if (!state.exhausted)
        await scanArchive({
            path: values.archive,
            digest,
            state,
            maxRecords: max,
            encodeBatch: (records) => JSON.stringify({source: "cve", records, baseline: binding}),
            send: async (body) => {
                await post("/internal/ingest", body);
                if (!values["dry-run"]) await Bun.sleep(delay);
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
        }) + "\n",
    );
}
run().catch((error) => {
    process.stderr.write(
        `${error instanceof Error ? error.message : "bootstrap failed"}\n`,
    );
    process.exitCode = 1;
});
