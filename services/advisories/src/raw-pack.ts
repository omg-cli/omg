import type { RawStore } from "./storage";
import { LIMITS, boundedBody, decodeUtf8, sha256 } from "./domain";

const prefix = "cve-pack-v1/";
const pointerPattern = /^(cve-pack-v1\/[a-f0-9]{64}\.raw)#(0|[1-9]\d{0,15}):([1-9]\d{0,15}):([a-f0-9]{64})$/;

export async function packRecords(records: readonly string[]): Promise<{key:string;body:string;pointers:readonly string[]}> {
    if (records.length < 1 || records.length > 64) throw new Error("invalid packed raw record count");
    let total = 0;
    const parts = records.map((raw) => {
        const bytes = new TextEncoder().encode(raw);
        if (bytes.length < 1 || bytes.length > LIMITS.cveRecord || decodeUtf8(bytes) !== raw)
            throw new Error("invalid packed raw UTF8 record");
        const offset = total;
        total += bytes.length;
        if (total > LIMITS.batch) throw new Error("packed raw records exceed batch byte bound");
        return { bytes, offset };
    });
    const body = records.join("");
    const key = `${prefix}${await sha256(body)}.raw`;
    const pointers = await Promise.all(parts.map(async ({bytes, offset}) =>
        `${key}#${offset}:${bytes.length}:${await sha256(bytes)}`));
    return {key, body, pointers};
}

export function r2Raw(bucket: Pick<R2Bucket, "get" | "put">): RawStore {
    return {
        put: (key, value) => bucket.put(key, value),
        get: async (key) => {
            if (!key.startsWith("cve-pack-")) return bucket.get(key);
            const match = pointerPattern.exec(key);
            if (!match) throw new Error("invalid packed raw pointer");
            const [, objectKey, offsetText, lengthText, digest] = match;
            if (!objectKey || offsetText === undefined || !lengthText || !digest)
                throw new Error("invalid packed raw pointer");
            const offset = Number(offsetText), length = Number(lengthText);
            if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) ||
                length > LIMITS.cveRecord || offset + length > LIMITS.batch)
                throw new Error("invalid packed raw pointer");
            const object = await bucket.get(objectKey, {range:{offset, length}});
            if (!object) throw new Error("packed raw object missing");
            if (!("body" in object)) throw new Error("packed raw body missing");
            const range = object.range;
            if (!range || !("offset" in range) || !("length" in range) ||
                range.offset !== offset || range.length !== length ||
                object.size < offset + length || object.size > LIMITS.batch) {
                await object.body.cancel();
                throw new Error("packed raw range mismatch");
            }
            const text = await boundedBody(object.body, length);
            if (new TextEncoder().encode(text).length !== length)
                throw new Error("packed raw range mismatch");
            if (await sha256(text) !== digest) throw new Error("packed raw digest mismatch");
            return {text: async () => text, verifiedSha256: digest};
        },
    };
}
