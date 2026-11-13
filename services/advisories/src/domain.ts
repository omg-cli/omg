export const LIMITS = {
    record: 1024 * 1024,
    batch: 4 * 1024 * 1024,
    records: 8,
    feed: 16 * 1024 * 1024,
    deltaRecords: 4,
    entries: 100_000,
};
export const SOURCES = {
    cve: "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json",
    arch: "https://security.archlinux.org/issues/all.json",
    kev: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
};
export type Feed = keyof typeof SOURCES;
export function object(value: unknown): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        throw new Error("expected object");
    return value as Record<string, unknown>;
}
export function string(value: unknown): string {
    if (typeof value !== "string") throw new Error("expected string");
    return value;
}
export function date(value: unknown): string {
    const text = string(value);
    const match =
        /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)?$/.exec(
            text,
        );
    if (!match) throw new Error("invalid date");
    const year = Number(match[1]),
        month = Number(match[2]),
        day = Number(match[3]);
    if (
        month < 1 ||
        month > 12 ||
        day < 1 ||
        day > new Date(Date.UTC(year, month, 0)).getUTCDate() ||
        Number(match[4]) > 23 ||
        Number(match[5]) > 59 ||
        Number(match[6]) > 59
    )
        throw new Error("invalid date");
    const parsed = new Date(match[7] ? text : `${text}Z`);
    if (!Number.isFinite(parsed.getTime())) throw new Error("invalid date");
    return parsed.toISOString();
}
export function cveId(value: unknown): string {
    const id = string(value);
    if (!/^CVE-\d{4}-\d{4,19}$/.test(id)) throw new Error("invalid CVE id");
    return id;
}
export function cveUrl(id: string): string {
    cveId(id);
    const [, year, number] = id.split("-");
    if (!number || !year) throw new Error("invalid CVE id");
    return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${number.slice(0, -3)}xxx/${id}.json`;
}
export async function sha256(value: string | Uint8Array): Promise<string> {
    const bytes =
        typeof value === "string"
            ? new TextEncoder().encode(value)
            : Uint8Array.from(value);
    return Array.from(
        new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
        (byte) => byte.toString(16).padStart(2, "0"),
    ).join("");
}
export async function boundedBody(
    body: ReadableStream<Uint8Array> | null,
    limit: number,
): Promise<string> {
    if (!body) throw new Error("missing body");
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let length = 0;
    try {
        while (true) {
            const part = await reader.read();
            if (part.done) break;
            length += part.value.byteLength;
            if (length > limit) {
                await reader.cancel();
                throw new Error("body exceeds limit");
            }
            chunks.push(part.value);
        }
    } finally {
        reader.releaseLock();
    }
    const result = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }
    return decodeUtf8(result);
}
export function decodeUtf8(bytes: Uint8Array): string {
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.startsWith("\uFEFF")) throw new Error("invalid UTF8 BOM");
    return text;
}
export function parseCve(raw: string, expectedId?: string) {
    if (new TextEncoder().encode(raw).length > LIMITS.record)
        throw new Error("record exceeds limit");
    const payload = object(JSON.parse(raw));
    const metadata = object(payload.cveMetadata);
    const id = cveId(metadata.cveId);
    if (expectedId && id !== expectedId) throw new Error("CVE id mismatch");
    if (payload.dataType !== "CVE_RECORD") throw new Error("invalid dataType");
    const schema = string(payload.dataVersion);
    const state = string(metadata.state);
    const modified = date(metadata.dateUpdated);
    const published =
        metadata.datePublished === undefined
            ? null
            : date(metadata.datePublished);
    const containers = object(payload.containers);
    object(containers.cna);
    if (containers.adp !== undefined && !Array.isArray(containers.adp))
        throw new Error("invalid ADP");
    const supported =
        ["5.0", "5.1", "5.1.1", "5.2", "5.2.0"].includes(schema) &&
        ["PUBLISHED", "REJECTED"].includes(state);
    if (state === "PUBLISHED" && !published)
        throw new Error("published record missing publication date");
    return { id, schema, state, modified, published, supported, payload };
}
export function parseArch(raw: string): unknown[] {
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value) || value.length > 50_000)
        throw new Error("invalid Arch snapshot");
    for (const item of value) {
        const issue = object(item);
        if (
            !/^AVG-\d+$/.test(string(issue.name)) ||
            !Array.isArray(issue.packages) ||
            issue.packages.length === 0 ||
            !issue.packages.every(
                (v) => typeof v === "string" && v.length > 0,
            ) ||
            !Array.isArray(issue.issues) ||
            !issue.issues.every(
                (v) => typeof v === "string" && /^CVE-\d{4}-\d{4,19}$/.test(v),
            )
        )
            throw new Error("invalid Arch issue");
        for (const key of ["status", "severity", "type"]) string(issue[key]);
        if (
            !["Fixed", "Not affected", "Unknown", "Vulnerable"].includes(
                string(issue.status),
            )
        )
            throw new Error("invalid Arch status");
        for (const key of ["affected", "fixed"])
            if (issue[key] !== null) string(issue[key]);
    }
    return value;
}
export function parseKev(raw: string) {
    const value = object(JSON.parse(raw));
    const revision = string(value.catalogVersion);
    date(value.dateReleased);
    if (
        !Array.isArray(value.vulnerabilities) ||
        value.vulnerabilities.length > 50_000 ||
        value.count !== value.vulnerabilities.length
    )
        throw new Error("invalid KEV catalog");
    const entries = value.vulnerabilities.map((v) => {
        const entry = object(v);
        cveId(entry.cveID);
        return entry;
    });
    return { revision, entries };
}
export type DeltaItem = { event: string; id: string; url: string };
export function parseDelta(raw: string): DeltaItem[] {
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value) || value.length > LIMITS.entries)
        throw new Error("invalid delta log");
    const entries: DeltaItem[] = [];
    for (const item of value) {
        const event = object(item);
        const time = date(event.fetchTime);
        if (!Array.isArray(event.error) || event.error.length > 0)
            throw new Error("upstream delta errors");
        if (
            !Array.isArray(event.new) ||
            !Array.isArray(event.updated) ||
            event.numberOfChanges !== event.new.length + event.updated.length
        )
            throw new Error("delta count mismatch");
        for (const change of [...event.new, ...event.updated]) {
            const record = object(change);
            const id = cveId(record.cveId);
            const url = cveUrl(id);
            if (record.githubLink !== url)
                throw new Error("untrusted delta URL");
            date(record.dateUpdated);
            entries.push({ event: time, id, url });
            if (entries.length > LIMITS.entries)
                throw new Error("too many delta records");
        }
    }
    return entries.sort(
        (a, b) => a.event.localeCompare(b.event) || a.id.localeCompare(b.id),
    );
}
