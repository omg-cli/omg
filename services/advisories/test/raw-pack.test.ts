import { expect, test } from "bun:test";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { fileURLToPath, URL as NodeURL } from "node:url";
import { LIMITS, object, sha256, string } from "../src/domain";
import { packRecords } from "../src/raw-pack";

test("immutable raw packs preserve exact UTF8 byte boundaries and individual digests", async () => {
    const records = ["{\"title\":\"π,世界,🦀\"}\r\n", "{\"title\":\"second\"}"];
    const packed = await packRecords(records);
    expect(packed.body).toBe(records.join(""));
    expect(packed.key).toBe(`cve-pack-v1/${await sha256(packed.body)}.raw`);
    let offset = 0;
    const bytes = new TextEncoder().encode(packed.body);
    for (const [index, raw] of records.entries()) {
        const length = new TextEncoder().encode(raw).length;
        expect(packed.pointers[index]).toBe(`${packed.key}#${offset}:${length}:${await sha256(raw)}`);
        expect(new TextDecoder("utf-8", {fatal:true, ignoreBOM:true}).decode(bytes.slice(offset, offset + length))).toBe(raw);
        offset += length;
    }
    expect(await packRecords(records)).toEqual(packed);
});

test("packs retain existing record count and exact aggregate byte bounds", async () => {
    expect((await packRecords(Array(64).fill("x"))).pointers).toHaveLength(64);
    const atLimit = await packRecords(["x".repeat(LIMITS.cveRecord), "y".repeat(LIMITS.batch-LIMITS.cveRecord)]);
    expect(new TextEncoder().encode(atLimit.body).length).toBe(LIMITS.batch);
    for (const records of [[], [""], Array(65).fill("x"), ["x".repeat(LIMITS.cveRecord+1)], ["x".repeat(LIMITS.cveRecord), "y".repeat(LIMITS.batch-LIMITS.cveRecord+1)], ["\ud800"], ["\ufeff{}"]]) {
        await expect(packRecords(records)).rejects.toThrow();
    }
});

test("real R2 range reader preserves legacy keys and refuses corrupt packed evidence", async () => {
    const build = await Bun.build({entrypoints:[fileURLToPath(new NodeURL("./raw-pack-worker-fixture.ts", import.meta.url))],target:"browser"});
    expect(build.success).toBe(true);
    const output = build.outputs[0];
    if (!output) throw new Error("missing bundled raw reader fixture");
    const runtime = new Miniflare(convertV4MiniflareOptions({modules:true, script:await output.text(), compatibilityDate:"2026-11-13", r2Buckets:["RAW"]}));
    try {
        const bucket = await runtime.getR2Bucket("RAW");
        const worker = await runtime.getWorker();
        async function read(key: string): Promise<string | null> {
            const response = await worker.fetch(`https://raw.example/?key=${encodeURIComponent(key)}`);
            const payload = object(await response.json());
            if (!response.ok) throw new Error(string(payload.error));
            return payload.text === null ? null : string(payload.text);
        }
        const records = ["π controlled first bytes", "second exact record"];
        const packed = await packRecords(records);
        await bucket.put("cve/legacy/hash.json", "legacy original bytes");
        expect(await read("cve/legacy/hash.json")).toBe("legacy original bytes");
        expect(await read("cve/missing/hash.json")).toBeNull();
        await bucket.put(packed.key, packed.body);
        for (const [index, expected] of records.entries()) {
            const pointer = packed.pointers[index];
            if (!pointer) throw new Error("missing controlled range pointer");
            expect(await read(pointer)).toBe(expected);
        }
        const first = packed.pointers[0];
        if (!first) throw new Error("missing controlled first pointer");
        const suffix = first.slice(first.indexOf("#"));
        for (const pointer of [packed.key, packed.key.replace("v1/", "v2/") + suffix, `${packed.key}#01:2:${"a".repeat(64)}`, `${packed.key}#-1:2:${"a".repeat(64)}`, `${packed.key}#0:0:${"a".repeat(64)}`, `${packed.key}#0:${LIMITS.cveRecord+1}:${"a".repeat(64)}`, `${packed.key}#${LIMITS.batch}:1:${"a".repeat(64)}`, `${packed.key}#9007199254740993:1:${"a".repeat(64)}`, `${packed.key}#0:1:${"A".repeat(64)}`, first + ":extra"]) {
            await expect(read(pointer)).rejects.toThrow("invalid packed raw pointer");
        }
        await expect(read(first.slice(0, -64) + "0".repeat(64))).rejects.toThrow("digest mismatch");
        const wrongOffset = `${packed.key}#1:1:${await sha256("x")}`;
        await expect(read(wrongOffset)).rejects.toThrow();
        const truncatedKey = `cve-pack-v1/${"b".repeat(64)}.raw`;
        await bucket.put(truncatedKey, "x");
        await expect(read(truncatedKey + suffix)).rejects.toThrow("range mismatch");
        const missingKey = `cve-pack-v1/${"c".repeat(64)}.raw`;
        await expect(read(missingKey + suffix)).rejects.toThrow("object missing");
        await bucket.put(packed.key, packed.body.replace("controlled", "CORRUPTED!"));
        await expect(read(first)).rejects.toThrow("digest mismatch");
    } finally { await runtime.dispose(); }
}, 30_000);
