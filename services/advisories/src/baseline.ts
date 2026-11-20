import { boundedBody, cveId, isGitHubInstallationToken, object, sha256 } from "./domain";
import type { Fetcher } from "./ingestion";
import { Store, type Command } from "./storage";

export type BaselineBinding = { digest: string; instance_id: string; session_id: string; endpoint: string; baseline_at: string };
export class BaselineBusyError extends Error {}
type Receipt = BaselineBinding & { exhausted: number; caught_up: number; completed_at: string | null; accepted: number };
type Proof = { session_id: string; release_tag: string; asset_name: string; asset_size: number; archive_digest: string;
    commit_sha: string; root_tree_sha: string; cves_tree_sha: string; phase: "traversing" | "reconciling" | "verified";
    expected_count: number; verified_count: number; after_id: string; verified_at: string | null };
type Tree = { path: string; tree_sha: string };
type Entry = { path: string; sha: string; type: "tree" | "blob"; mode: "040000" | "100644" };
const prefix = "/repos/CVEProject/cvelistV5/";
const hashPattern = /^[a-f0-9]{40}$/;
function gitHash(value: unknown): string {
    if (typeof value !== "string" || !hashPattern.test(value)) throw new Error("invalid publisher Git identity");
    return value;
}
export async function gitBlobSha1(raw: string): Promise<string> {
    const payload = new TextEncoder().encode(raw);
    const header = new TextEncoder().encode(`blob ${payload.byteLength}\0`);
    const bytes = new Uint8Array(header.length + payload.length);
    bytes.set(header); bytes.set(payload, header.length);
    return [...new Uint8Array(await crypto.subtle.digest("SHA-1", bytes))].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
export async function baselineImportCommands(store: Store, session: string, records: readonly { id: string; raw: string }[]): Promise<Command[]> {
    const rows = await Promise.all(records.map(async ({ id, raw }) => ({ id, hash: await sha256(raw), git: await gitBlobSha1(raw) })));
    const encoded = JSON.stringify(rows);
    const conflict = await store.sql.first<{ cve_id: string }>(
        "SELECT b.cve_id FROM json_each(?) j CROSS JOIN baseline_member b ON b.session_id=? AND b.cve_id=json_extract(j.value,'$.id') WHERE b.payload_sha256<>json_extract(j.value,'$.hash') LIMIT 1", [encoded, session]);
    if (conflict) throw new Error("baseline original payload mismatch");
    return [
        { sql: "INSERT INTO baseline_member(session_id,cve_id,payload_sha256) SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.hash') FROM json_each(?) WHERE 1 ON CONFLICT(session_id,cve_id) DO NOTHING", values: [session, encoded] },
        { sql: "INSERT INTO baseline_import_blob(session_id,cve_id,payload_sha256,git_blob_sha1) SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.hash'),json_extract(value,'$.git') FROM json_each(?) WHERE 1 ON CONFLICT(session_id,cve_id) DO NOTHING", values: [session, encoded] },
        { sql: "UPDATE baseline_receipt SET caught_up=0,completed_at=NULL WHERE session_id=?", values: [session] },
        { sql: "UPDATE source_checkpoint SET bootstrap_complete=0 WHERE source='cve'", values: [] },
        { sql: "UPDATE baseline_publisher_proof SET phase=CASE WHEN phase='traversing' THEN phase ELSE 'reconciling' END,after_id='',verified_count=0,verified_at=NULL WHERE session_id=?", values: [session] },
    ];
}
function entries(value: unknown, sha: string): Entry[] {
    const data = object(value);
    if (data.sha !== sha || data.truncated !== false || !Array.isArray(data.tree) || data.tree.length > 4096)
        throw new Error("invalid or truncated publisher tree");
    const paths = new Set<string>();
    return data.tree.map((item) => {
        const row = object(item);
        if (typeof row.path !== "string" || !/^[A-Za-z0-9_.-]{1,200}$/.test(row.path) || row.path === "." || row.path === ".." || paths.has(row.path))
            throw new Error("invalid duplicate publisher tree path");
        paths.add(row.path);
        if (!((row.type === "tree" && row.mode === "040000") || (row.type === "blob" && row.mode === "100644")))
            throw new Error("invalid publisher tree mode");
        return { path: row.path, sha: gitHash(row.sha), type: row.type, mode: row.mode };
    });
}
async function activeReceipt(store: Store, input: Record<string, unknown>, endpoint: string): Promise<Receipt> {
    const receipt = await store.sql.first<Receipt>("SELECT * FROM baseline_receipt WHERE digest=?", [typeof input.digest === "string" ? input.digest : ""]);
    const checkpoint = await store.checkpoint("cve");
    if (!receipt || receipt.endpoint !== endpoint || input.endpoint !== endpoint || receipt.instance_id !== input.instance_id ||
        receipt.session_id !== input.session_id || checkpoint?.baseline_digest !== receipt.digest) throw new Error("invalid baseline session binding");
    return receipt;
}
export async function verifyBaseline(value: unknown, store: Store, endpoint: string, now: string, fetcher: Fetcher) {
    const input = object(value);
    const allowed = new Set(["digest", "instance_id", "session_id", "endpoint", "release_tag", "asset", "github_token", "started", "baseline_at"]);
    if (Object.keys(input).some((key) => !allowed.has(key)) || !isGitHubInstallationToken(input.github_token))
        throw new Error("invalid baseline verification credential or fields");
    const token = input.github_token;
    const initial = await activeReceipt(store, input, endpoint);
    const day = initial.baseline_at.slice(0, 10);
    if (initial.baseline_at !== `${day}T00:00:00.000Z` || input.release_tag !== `cve_${day}_0000Z` ||
        (input.asset !== `${day}_all_CVEs_at_midnight.zip` && input.asset !== `${day}_all_CVEs_at_midnight.zip.zip`))
        throw new Error("invalid baseline publisher release");
    const releaseTag = input.release_tag;
    const assetName = input.asset;
    const owner = crypto.randomUUID();
    if (!await store.lease("cve", owner, now)) throw new BaselineBusyError("baseline verification busy");
    const writer = store.writer("cve", owner);
    let bytesRead = 0;
    const signal = AbortSignal.timeout(25_000);
    async function read(path: string) {
        if (!new RegExp(`^${prefix}(?:releases/tags/cve_\\d{4}-\\d{2}-\\d{2}_0000Z|git/ref/tags/cve_\\d{4}-\\d{2}-\\d{2}_0000Z|git/(?:commits|trees)/[a-f0-9]{40})$`).test(path))
            throw new Error("invalid publisher request path");
        const response = await fetcher(`https://api.github.com${path}`, { method: "GET", redirect: "manual", signal,
            headers: { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "user-agent": "omg-advisories-baseline/1", "x-github-api-version": "2022-11-28" } });
        if (!response.ok) throw new Error(`publisher HTTP ${response.status}`);
        const raw = await boundedBody(response.body, 2 * 1024 ** 2);
        bytesRead += new TextEncoder().encode(raw).length;
        if (bytesRead > 16 * 1024 ** 2 || raw.includes(token)) throw new Error("invalid publisher response bounds");
        const hash = await sha256(raw);
        const key = `baseline-proof/${initial.session_id}/${hash}.json`;
        await writer.raw.put(key, raw);
        return { data: object(JSON.parse(raw)), key, hash };
    }
    try {
        const receipt = await activeReceipt(writer, input, endpoint);
        let proof = await writer.sql.first<Proof>("SELECT * FROM baseline_publisher_proof WHERE session_id=?", [receipt.session_id]);
        if (!proof) {
            const release = await read(`${prefix}releases/tags/${releaseTag}`);
            if (release.data.tag_name !== releaseTag || !Array.isArray(release.data.assets)) throw new Error("invalid publisher release metadata");
            const assets = release.data.assets.map(object).filter((asset) => asset.name === assetName);
            const asset = assets[0];
            if (assets.length !== 1 || !asset || asset.digest !== `sha256:${receipt.digest}` || typeof asset.size !== "number" || !Number.isSafeInteger(asset.size) || asset.size < 1 || asset.size > 1024 ** 3)
                throw new Error("baseline publisher archive digest mismatch");
            const ref = await read(`${prefix}git/ref/tags/${releaseTag}`);
            const target = object(ref.data.object);
            if (target.type !== "commit") throw new Error("invalid publisher release commit");
            const commitSha = gitHash(target.sha);
            const commit = await read(`${prefix}git/commits/${commitSha}`);
            if (commit.data.sha !== commitSha) throw new Error("invalid publisher commit identity");
            const rootSha = gitHash(object(commit.data.tree).sha);
            const root = await read(`${prefix}git/trees/${rootSha}`);
            const cves = entries(root.data, rootSha).find((entry) => entry.path === "cves");
            if (cves?.type !== "tree") throw new Error("invalid publisher cves root");
            const provenance = JSON.stringify({ release: { key: release.key, sha256: release.hash }, ref: { key: ref.key, sha256: ref.hash }, commit: { key: commit.key, sha256: commit.hash }, root: { key: root.key, sha256: root.hash } });
            const provenanceHash = await sha256(provenance), provenanceKey = `baseline-proof/${receipt.session_id}/${provenanceHash}.json`;
            await writer.raw.put(provenanceKey, provenance);
            await writer.sql.batch([
                { sql: "INSERT INTO baseline_publisher_proof(session_id,release_tag,asset_name,asset_size,archive_digest,commit_sha,root_tree_sha,cves_tree_sha,provenance_key,provenance_sha256,phase,checked_at) VALUES(?,?,?,?,?,?,?,?,?,?,'traversing',?)", values: [receipt.session_id, releaseTag, assetName, asset.size, receipt.digest, commitSha, rootSha, cves.sha, provenanceKey, provenanceHash, now] },
                { sql: "INSERT INTO baseline_publisher_tree(session_id,path,tree_sha) VALUES(?,'cves',?)", values: [receipt.session_id, cves.sha] },
            ]);
            proof = await writer.sql.first<Proof>("SELECT * FROM baseline_publisher_proof WHERE session_id=?", [receipt.session_id]);
        }
        if (!proof || proof.release_tag !== releaseTag || proof.asset_name !== assetName || proof.archive_digest !== receipt.digest) throw new Error("baseline publisher proof binding mismatch");
        for (let step = 0; proof.phase === "traversing" && step < 8; step++) {
            const tree = await writer.sql.first<Tree>("SELECT path,tree_sha FROM baseline_publisher_tree WHERE session_id=? AND done=0 ORDER BY path LIMIT 1", [receipt.session_id]);
            if (!tree) {
                await writer.sql.batch([{ sql: "UPDATE baseline_publisher_proof SET phase='reconciling',checked_at=? WHERE session_id=?", values: [now, receipt.session_id] }]);
                proof.phase = "reconciling"; break;
            }
            const fetched = await read(`${prefix}git/trees/${gitHash(tree.tree_sha)}`);
            const children: { path: string; sha: string }[] = [], members: { id: string; path: string; sha: string }[] = [];
            for (const entry of entries(fetched.data, tree.tree_sha)) {
                const parts = tree.path.split("/");
                if (parts.length === 1) {
                    if (entry.type === "blob" && (entry.path === "delta.json" || entry.path === "deltaLog.json")) continue;
                    if (entry.type !== "tree" || !/^\d{4}$/.test(entry.path)) throw new Error("invalid publisher year member");
                } else if (parts.length === 2) {
                    if (entry.type !== "tree" || !/^\d{1,16}xxx$/.test(entry.path)) throw new Error("invalid publisher group member");
                } else if (parts.length === 3) {
                    if (entry.type !== "blob" || !entry.path.endsWith(".json")) throw new Error("invalid publisher CVE member");
                    const id = cveId(entry.path.slice(0, -5)), match = /^CVE-(\d{4})-(\d+)$/.exec(id);
                    if (!match || match[1] !== parts[1] || `${match[2]?.slice(0, -3)}xxx` !== parts[2]) throw new Error("publisher CVE path mismatch");
                    members.push({ id, path: `${tree.path}/${entry.path}`, sha: entry.sha }); continue;
                } else throw new Error("invalid publisher tree depth");
                children.push({ path: `${tree.path}/${entry.path}`, sha: entry.sha });
            }
            await writer.sql.batch([
                { sql: "INSERT INTO baseline_publisher_tree(session_id,path,tree_sha) SELECT ?,json_extract(value,'$.path'),json_extract(value,'$.sha') FROM json_each(?)", values: [receipt.session_id, JSON.stringify(children)] },
                { sql: "INSERT INTO baseline_expected_member(session_id,cve_id,path,git_blob_sha1) SELECT ?,json_extract(value,'$.id'),json_extract(value,'$.path'),json_extract(value,'$.sha') FROM json_each(?)", values: [receipt.session_id, JSON.stringify(members)] },
                { sql: "UPDATE baseline_publisher_tree SET done=1,object_key=?,payload_sha256=? WHERE session_id=? AND path=?", values: [fetched.key, fetched.hash, receipt.session_id, tree.path] },
                { sql: "UPDATE baseline_publisher_proof SET expected_count=expected_count+?,checked_at=? WHERE session_id=?", values: [members.length, now, receipt.session_id] },
            ]);
            proof.expected_count += members.length;
        }
        const pending = await writer.sql.first<{ count: number }>("SELECT COUNT(*) AS count FROM baseline_publisher_tree WHERE session_id=? AND done=0", [receipt.session_id]);
        let phase: string = proof.phase;
        if (pending?.count === 0 && proof.phase === "traversing") {
            await writer.sql.batch([{ sql: "UPDATE baseline_publisher_proof SET phase='reconciling',checked_at=? WHERE session_id=?", values: [now, receipt.session_id] }]);
            proof.phase = "reconciling"; phase = proof.phase;
        }
        if (proof.phase === "reconciling") {
            phase = receipt.exhausted === 1 && receipt.caught_up === 1 ? "reconciling" : "awaiting_import";
            for (let page = 0; phase === "reconciling" && page < 8; page++) {
                const rows = await writer.sql.all<{ cve_id: string; expected_sha: string; member_sha: string | null; import_sha: string | null; git_sha: string | null }>(
                    "SELECT e.cve_id,e.git_blob_sha1 AS expected_sha,b.payload_sha256 AS member_sha,i.payload_sha256 AS import_sha,i.git_blob_sha1 AS git_sha FROM baseline_expected_member e LEFT JOIN baseline_member b ON b.session_id=e.session_id AND b.cve_id=e.cve_id LEFT JOIN baseline_import_blob i ON i.session_id=e.session_id AND i.cve_id=e.cve_id WHERE e.session_id=? AND e.cve_id>? ORDER BY e.cve_id LIMIT 512", [receipt.session_id, proof.after_id]);
                if (!rows.length) {
                    const counts = await writer.sql.first<{ members: number; blobs: number; unsupported: number }>("SELECT (SELECT COUNT(*) FROM baseline_member WHERE session_id=?) AS members,(SELECT COUNT(*) FROM baseline_import_blob WHERE session_id=?) AS blobs,(SELECT COUNT(*) FROM source_record WHERE supported=0) AS unsupported", [receipt.session_id, receipt.session_id]);
                    if (!counts || proof.expected_count < 1 || counts.members !== proof.expected_count || counts.blobs !== proof.expected_count || receipt.accepted !== proof.expected_count || proof.verified_count !== proof.expected_count) throw new Error("baseline publisher membership count mismatch");
                    if (counts.unsupported) throw new Error("unsupported records prevent completeness");
                    const checkpoint = await writer.checkpoint("cve");
                    const age = checkpoint?.checked_at ? Date.parse(now) - Date.parse(checkpoint.checked_at) : Infinity;
                    if (!checkpoint?.complete || checkpoint.error || age < 0 || age > 30 * 60_000 || !receipt.completed_at || !checkpoint.checked_at || checkpoint.checked_at < receipt.completed_at) { phase = "awaiting_catchup"; break; }
                    await writer.sql.batch([
                        { sql: "UPDATE baseline_publisher_proof SET phase='verified',verified_at=?,checked_at=? WHERE session_id=?", values: [now, now, receipt.session_id] },
                        { sql: "UPDATE source_checkpoint SET bootstrap_complete=1 WHERE source='cve' AND baseline_digest=?", values: [receipt.digest] },
                    ]);
                    proof.phase = "verified"; phase = "verified"; break;
                }
                if (rows.some((row) => row.member_sha === null || row.import_sha === null || row.git_sha === null)) { phase = "awaiting_import"; break; }
                if (rows.some((row) => row.member_sha !== row.import_sha || row.expected_sha !== row.git_sha)) throw new Error("baseline publisher original Git blob mismatch");
                const last = rows.at(-1);
                if (!last) throw new Error("invalid publisher reconciliation page");
                proof.after_id = last.cve_id; proof.verified_count += rows.length;
                await writer.sql.batch([{ sql: "UPDATE baseline_publisher_proof SET after_id=?,verified_count=?,checked_at=? WHERE session_id=?", values: [proof.after_id, proof.verified_count, now, receipt.session_id] }]);
            }
        }
        return { schema_version: 1, phase, expected_count: proof.expected_count, verified_count: proof.verified_count, pending_trees: pending?.count ?? 0,
            archive_verified: proof.phase === "verified", commit_sha: proof.commit_sha, release_tag: proof.release_tag, asset: proof.asset_name, digest: proof.archive_digest };
    } catch (error) {
        throw new Error((error instanceof Error ? error.message : "publisher verification failed").replaceAll(token, "[redacted]"));
    } finally { await store.release("cve", owner); }
}
