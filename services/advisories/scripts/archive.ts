import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { crc32 } from "node:zlib";
import { stat, mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openPromise } from "yauzl";
import { LIMITS, parseCve, decodeUtf8 } from "../src/domain";
export type ArchiveState = {
    digest: string;
    next_entry: number;
    accepted: number;
    exhausted: boolean;
    finished_at: string | null;
};
export async function fileHash(path: string) {
    const info = await stat(path);
    if (info.size > 1024 ** 3)
        throw new Error("archive exceeds 1 GiB operator budget");
    const hash = createHash("sha256");
    let bytes = 0;
    for await (const chunk of createReadStream(path)) {
        bytes += chunk.length;
        if (bytes > 1024 ** 3)
            throw new Error("archive exceeds 1 GiB operator budget");
        hash.update(chunk);
    }
    return hash.digest("hex");
}
async function corpusArchive(snapshot: string, directory: string): Promise<string> {
    const outer = await openPromise(snapshot, {
        lazyEntries: true, autoClose: false, strictFileNames: true, validateEntrySizes: true,
    });
    try {
        if (outer.entryCount !== 1) return snapshot;
        for await (const entry of outer.eachEntry()) {
            if (entry.fileName !== "cves.zip") return snapshot;
            if (
                entry.uncompressedSize > 1024 ** 3 ||
                entry.uncompressedSize / Math.max(1, entry.compressedSize) > 500 ||
                (entry.generalPurposeBitFlag & 1) !== 0 ||
                ![0, 8].includes(entry.compressionMethod)
            ) throw new Error("invalid or oversize CVE archive wrapper");
            const inner = join(directory, "corpus.zip");
            const output = await open(inner, "wx", 0o600);
            try {
                const stream = await outer.openReadStreamPromise(entry);
                let bytes = 0;
                let checksum = 0;
                try {
                    for await (const chunk of stream) {
                        const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                        bytes += data.length;
                        if (bytes > 1024 ** 3) throw new Error("archive wrapper expansion exceeds budget");
                        checksum = crc32(data, checksum);
                        await output.writeFile(data);
                    }
                } finally { stream.destroy(); }
                if (bytes !== entry.uncompressedSize || checksum !== entry.crc32)
                    throw new Error("archive wrapper size or checksum mismatch");
            } finally { await output.close(); }
            return inner;
        }
        return snapshot;
    } finally { outer.close(); }
}
export async function scanArchive(options: {
    path: string;
    digest: string;
    state: ArchiveState;
    maxRecords: number;
    encodeBatch: (records: string[]) => string;
    send: (body: string) => Promise<void>;
    save: (state: ArchiveState) => Promise<void>;
}) {
    if (options.state.digest !== options.digest)
        throw new Error("archive digest mismatch");
    const emptyBody = options.encodeBatch([]);
    if (Buffer.byteLength(emptyBody) > LIMITS.batch)
        throw new Error("encoded ingest batch exceeds limit");
    const directory = await mkdtemp(join(tmpdir(), "omg-advisory-verified-"));
    const snapshot = join(directory, "archive.zip");
    try {
        const output = await open(snapshot, "wx", 0o600);
        try {
            let copied = 0;
            for await (const chunk of createReadStream(options.path)) {
                copied += chunk.length;
                if (copied > 1024 ** 3) throw new Error("archive exceeds 1 GiB operator budget");
                await output.writeFile(chunk);
            }
        } finally {
            await output.close();
        }
        if (await fileHash(snapshot) !== options.digest) throw new Error("archive digest mismatch");
        const zip = await openPromise(await corpusArchive(snapshot, directory), {
            lazyEntries: true,
            strictFileNames: true,
            validateEntrySizes: true,
        });
        let index = 0;
        let scanned = 0;
        let corpusRecords = 0;
        let expanded = 0;
        let sent = 0;
        let pending: string[] = [];
        let pendingBody = emptyBody;
        let pendingNext = options.state.next_entry;
        let stop = false;
        async function flush() {
            if (!pending.length) return;
            await options.send(pendingBody);
            options.state.accepted += pending.length;
            sent += pending.length;
            options.state.next_entry = pendingNext;
            await options.save(options.state);
            pending = [];
            pendingBody = emptyBody;
        }
        try {
            if (zip.entryCount > 1_000_000)
                throw new Error("too many archive entries");
            for await (const entry of zip.eachEntry()) {
                const current = index++;
                scanned++;
                if (scanned > 1_000_000)
                    throw new Error("too many archive entries");
                if (entry.fileName === "cves.zip")
                    throw new Error("CVE archive wrapper must be sole and single-level");
                if (entry.fileName.endsWith("/")) continue;
                const match =
                    /(?:^|\/)cves\/(\d{4})\/([0-9]+xxx)\/(CVE-\d{4}-\d{4,19})\.json$/.exec(
                        entry.fileName,
                    );
                if (!match) {
                    if (/CVE-.*\.json$/.test(entry.fileName))
                        throw new Error("unexpected CVE record path");
                    continue;
                }
                corpusRecords++;
                if (current < options.state.next_entry) continue;
                if (sent + pending.length >= options.maxRecords) {
                    stop = true;
                    break;
                }
                if (
                    entry.uncompressedSize > LIMITS.record ||
                    entry.uncompressedSize / Math.max(1, entry.compressedSize) >
                        500 ||
                    (entry.generalPurposeBitFlag & 1) !== 0
                )
                    throw new Error(
                        "oversize, encrypted or excessive compression entry",
                    );
                expanded += entry.uncompressedSize;
                if (expanded > 8 * 1024 ** 3)
                    throw new Error("archive expansion exceeds budget");
                const stream = await zip.openReadStreamPromise(entry);
                const chunks: Buffer[] = [];
                let bytes = 0;
                for await (const chunk of stream) {
                    const data = Buffer.isBuffer(chunk)
                        ? chunk
                        : Buffer.from(chunk);
                    bytes += data.length;
                    if (bytes > LIMITS.record) {
                        stream.destroy();
                        throw new Error("record exceeds limit");
                    }
                    chunks.push(data);
                }
                const raw = decodeUtf8(Buffer.concat(chunks));
                const record = parseCve(raw, match[3]);
                const [, year, number] = record.id.split("-");
                if (
                    year !== match[1] ||
                    !number ||
                    `${number.slice(0, -3)}xxx` !== match[2]
                )
                    throw new Error("CVE path mismatch");
                if (!record.supported)
                    throw new Error("unsupported CVE schema or state");
                let body = options.encodeBatch([...pending, raw]);
                if (Buffer.byteLength(body) > LIMITS.batch) {
                    await flush();
                    body = options.encodeBatch([raw]);
                    if (Buffer.byteLength(body) > LIMITS.batch)
                        throw new Error("encoded ingest batch exceeds limit");
                }
                pending.push(raw);
                pendingBody = body;
                pendingNext = index;
                if (pending.length === LIMITS.records) await flush();
            }
            await flush();
            if (!stop) {
                if (corpusRecords === 0) throw new Error("archive contains no CVE records");
                options.state.next_entry = index;
                options.state.exhausted = true;
                options.state.finished_at = new Date().toISOString();
                await options.save(options.state);
            }
            return { sent, exhausted: options.state.exhausted };
        } finally {
            zip.close();
        }
    } finally {
        await rm(directory, { recursive: true, force: true });
    }
}
