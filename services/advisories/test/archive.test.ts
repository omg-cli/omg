import { test, expect } from "bun:test";
import { crc32, deflateRawSync } from "node:zlib";
import { parseBatch } from "../src/ingestion";
import { scanArchive, fileHash, type ArchiveState } from "../scripts/archive";
const encodeBatch = (records: string[]) => JSON.stringify({source: "cve", records});
const path = new URL("./fixtures/tiny.zip", import.meta.url).pathname;
test("tiny ZIP scans lazily, stops at record budget and resumes without extracting files", async () => {
    const digest = await fileHash(path);
    const state: ArchiveState = {
        digest,
        next_entry: 0,
        accepted: 0,
        exhausted: false,
        finished_at: null,
    };
    const received: string[] = [];
    let saves = 0;
    const options = {
        path,
        digest,
        state,
        maxRecords: 1,
        encodeBatch,
        send: async (body: string) => {
            received.push(...parseBatch(JSON.parse(body)));
        },
        save: async () => {
            saves++;
        },
    };
    expect(await scanArchive(options)).toEqual({ sent: 1, exhausted: false });
    expect(state.next_entry).toBe(1);
    expect(await scanArchive({ ...options, maxRecords: 4 })).toEqual({
        sent: 2,
        exhausted: true,
    });
    expect(state.accepted).toBe(3);
    expect(new Set(received).size).toBe(3);
    expect(saves).toBeGreaterThan(0);
});
test("archive hash and year mismatch fail before accepting records", async () => {
    let sends = 0;
    const state: ArchiveState = {
        digest: "a".repeat(64),
        next_entry: 0,
        accepted: 0,
        exhausted: false,
        finished_at: null,
    };
    await expect(
        scanArchive({
            path,
            digest: state.digest,
            state,
            maxRecords: 1,
            encodeBatch,
            send: async () => {
                sends++;
            },
            save: async () => {},
        }),
    ).rejects.toThrow("digest mismatch");
    const bad = new URL("./fixtures/wrong-year.zip", import.meta.url).pathname;
    const digest = await fileHash(bad);
    await expect(
        scanArchive({
            path: bad,
            digest,
            state: { ...state, digest },
            maxRecords: 1,
            encodeBatch,
            send: async () => {
                sends++;
            },
            save: async () => {},
        }),
    ).rejects.toThrow("path mismatch");
    expect(sends).toBe(0);
});
test("failed batch does not advance resumable archive position", async () => {
    const digest = await fileHash(path);
    const state: ArchiveState = {
        digest,
        next_entry: 0,
        accepted: 0,
        exhausted: false,
        finished_at: null,
    };
    await expect(
        scanArchive({
            path,
            digest,
            state,
            maxRecords: 3,
            encodeBatch,
            send: async () => {
                throw new Error("ingest unavailable");
            },
            save: async () => {},
        }),
    ).rejects.toThrow("ingest unavailable");
    expect(state.accepted).toBe(0);
    expect(state.next_entry).toBe(0);
});
test("archive mutation after verification cannot change the bytes being parsed", async () => {
    const {mkdtemp,copyFile,writeFile,rm} = await import("node:fs/promises");
    const {tmpdir} = await import("node:os");
    const {join} = await import("node:path");
    const directory = await mkdtemp(join(tmpdir(),"advisory-archive-test-"));
    const mutable = join(directory,"archive.zip");
    try {
        await copyFile(new URL("./fixtures/nine.zip",import.meta.url).pathname,mutable);
        const digest = await fileHash(mutable);
        const state: ArchiveState = {digest,next_entry:0,accepted:0,exhausted:false,finished_at:null};
        const records:string[] = [];
        await scanArchive({path:mutable,digest,state,maxRecords:20,encodeBatch,send:async(body)=>{
            records.push(...parseBatch(JSON.parse(body)));
            await writeFile(mutable,"corrupted original after first batch");
        },save:async()=>{}});
        expect(records.length).toBe(9);
        expect(state.exhausted).toBe(true);
    } finally {
        await rm(directory,{recursive:true,force:true});
    }
});
function storedZip(records: string[]): Buffer {
    return zipEntries(records.map((raw, index) => ({name: `cves/2026/1xxx/CVE-2026-${1234 + index}.json`, data: Buffer.from(raw)})));
}
function zipEntries(entries: {name: string; data: Buffer; deflate?: boolean; checksum?: number; declaredSize?: number}[]): Buffer {
    const files: Buffer[] = [];
    const directory: Buffer[] = [];
    let offset = 0;
    for (const entry of entries) {
        const name = Buffer.from(entry.name);
        const data = entry.deflate ? deflateRawSync(entry.data) : entry.data;
        const checksum = entry.checksum ?? crc32(entry.data);
        const method = entry.deflate ? 8 : 0;
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0);
        local.writeUInt16LE(20, 4);
        local.writeUInt16LE(method, 8);
        local.writeUInt32LE(checksum, 14);
        local.writeUInt32LE(data.length, 18);
        local.writeUInt32LE(entry.declaredSize ?? entry.data.length, 22);
        local.writeUInt16LE(name.length, 26);
        files.push(local, name, data);
        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0);
        central.writeUInt16LE(20, 4);
        central.writeUInt16LE(20, 6);
        central.writeUInt16LE(method, 10);
        central.writeUInt32LE(checksum, 16);
        central.writeUInt32LE(data.length, 20);
        central.writeUInt32LE(entry.declaredSize ?? entry.data.length, 24);
        central.writeUInt16LE(name.length, 28);
        central.writeUInt32LE(offset, 42);
        directory.push(central, name);
        offset += local.length + name.length + data.length;
    }
    const central = Buffer.concat(directory);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(entries.length, 8);
    end.writeUInt16LE(entries.length, 10);
    end.writeUInt32LE(central.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...files, central, end]);
}
test("archive batches budget the complete bound POST envelope at the byte limit", async () => {
    const { mkdtemp, writeFile, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { LIMITS, object } = await import("../src/domain");
    const records = Array.from({ length: 4 }, (_, index) => {
        const payload = {
            dataType: "CVE_RECORD", dataVersion: "5.2",
            cveMetadata: { cveId: `CVE-2026-${1234 + index}`, state: "PUBLISHED", dateUpdated: "2026-11-13T00:00:00Z", datePublished: "2026-11-13T00:00:00Z" },
            containers: { cna: { description: "" } },
        };
        payload.containers.cna.description = "x".repeat(1_048_500 - JSON.stringify(payload).length);
        return JSON.stringify(payload);
    });
    const baseline = { digest: "a".repeat(64), instance_id: "a".repeat(32), session_id: "a".repeat(36), endpoint: "https://advisories.example" };
    const encodeBatch = (batch: string[]) => JSON.stringify({source: "cve", records: batch, baseline});
    const directory = await mkdtemp(join(tmpdir(), "advisory-wire-test-"));
    const path = join(directory, "archive.zip");
    try {
        await writeFile(path, storedZip(records));
        const digest = await fileHash(path);
        const state: ArchiveState = {digest, next_entry: 0, accepted: 0, exhausted: false, finished_at: null};
        const received: string[] = [];
        const options = {
            path, digest, state, maxRecords: 4, encodeBatch,
            send: async (body: string) => {
                const request = new Request("https://advisories.example/internal/ingest", {method: "POST", body});
                const wire = await request.text();
                expect(Buffer.byteLength(wire)).toBeLessThanOrEqual(LIMITS.batch);
                const payload = object(JSON.parse(wire));
                expect(payload.baseline).toEqual(baseline);
                received.push(...parseBatch(JSON.parse(wire)));
            },
            save: async () => {},
        };
        await scanArchive(options);
        expect(received).toEqual(records);
        expect(state.accepted).toBe(4);
        expect(state.exhausted).toBe(true);
    } finally {
        await rm(directory, {recursive: true, force: true});
    }
});


test("publisher cves.zip wrapper resumes the inner corpus under the outer digest", async () => {
    const {mkdtemp, readFile, writeFile, rm} = await import("node:fs/promises");
    const {tmpdir} = await import("node:os");
    const {join} = await import("node:path");
    const directory = await mkdtemp(join(tmpdir(), "advisory-nested-test-"));
    try {
        const inner = await readFile(path);
        for (const deflate of [false, true]) {
            const archive = join(directory, "publisher.zip.zip");
            await writeFile(archive, zipEntries([{name: "cves.zip", data: inner, deflate}]));
            const digest = await fileHash(archive);
            const state: ArchiveState = {digest, next_entry: 0, accepted: 0, exhausted: false, finished_at: null};
            const received: string[] = [];
            const options = {path: archive, digest, state, maxRecords: 1, encodeBatch,
                send: async (body: string) => { received.push(...parseBatch(JSON.parse(body))); }, save: async () => {},
        };
        expect(await scanArchive(options)).toEqual({sent: 1, exhausted: false});
        expect(state.digest).toBe(digest);
        expect(await scanArchive({...options, maxRecords: 4})).toEqual({sent: 2, exhausted: true});
        expect(state.accepted).toBe(3);
        expect(new Set(received).size).toBe(3);
        expect(await scanArchive({...options, maxRecords: 4})).toEqual({sent: 0, exhausted: true});
        }
    } finally { await rm(directory, {recursive: true, force: true}); }
});

test("archive wrappers reject corrupt, mixed, recursive and empty corpora without completion", async () => {
    const {mkdtemp, readFile, writeFile, rm} = await import("node:fs/promises");
    const {tmpdir} = await import("node:os");
    const {join} = await import("node:path");
    const directory = await mkdtemp(join(tmpdir(), "advisory-invalid-wrapper-test-"));
    try {
        const inner = await readFile(path);
        const validWrapper = zipEntries([{name: "cves.zip", data: inner, deflate: true}]);
        const cases = [
            {name: "crc", data: zipEntries([{name: "cves.zip", data: inner, deflate: true, checksum: (crc32(inner) ^ 1) >>> 0}]), error: "checksum"},
            {name: "mixed", data: zipEntries([{name: "cves.zip", data: inner}, {name: "README", data: Buffer.from("mixed")}]), error: "wrapper"},
            {name: "recursive", data: zipEntries([{name: "cves.zip", data: validWrapper, deflate: true}]), error: "wrapper"},
            {name: "oversize", data: zipEntries([{name: "cves.zip", data: inner, deflate: true, declaredSize: 2 * 1024 ** 3}]), error: "oversize"},
            {name: "ratio", data: zipEntries([{name: "cves.zip", data: Buffer.alloc(512 * 1024), deflate: true}]), error: "oversize"},
            {name: "empty", data: zipEntries([{name: "README", data: Buffer.from("no records")}]), error: "no CVE records"},
        ];
        for (const fixture of cases) {
            const archive = join(directory, fixture.name + ".zip");
            await writeFile(archive, fixture.data);
            const digest = await fileHash(archive);
            const state: ArchiveState = {digest, next_entry: 0, accepted: 0, exhausted: false, finished_at: null};
            let sends = 0;
            await expect(scanArchive({path: archive, digest, state, maxRecords: 10, encodeBatch,
                send: async () => { sends++; }, save: async () => {},
            })).rejects.toThrow(fixture.error);
            expect(sends).toBe(0);
            expect(state.exhausted).toBe(false);
            expect(state.finished_at).toBeNull();
            if (fixture.name === "mixed") {
                state.next_entry = 2;
                state.accepted = 1;
                await expect(scanArchive({path: archive, digest, state, maxRecords: 10, encodeBatch,
                    send: async () => { sends++; }, save: async () => {},
                })).rejects.toThrow("wrapper");
                expect(sends).toBe(0);
            }
        }
    } finally { await rm(directory, {recursive: true, force: true}); }
});
