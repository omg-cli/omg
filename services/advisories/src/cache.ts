import { object, sha256 } from "./domain";

function publicRead(request: Request): boolean {
    return request.method === "GET" && !request.headers.has("authorization") &&
        !request.headers.has("cookie") &&
        /^\/v1\/(?:arch\/advisories|cves\/(?:recent|CVE-\d{4}-\d{4,19})|epss\/CVE-\d{4}-\d{4,19})$/.test(new URL(request.url).pathname);
}
function conditional(request: Request, response: Response): Response {
    const etag = response.headers.get("etag");
    const matches = request.headers.get("if-none-match")?.split(",")
        .some((tag) => tag.trim() === "*" || tag.trim().replace(/^W\//, "") === etag);
    return etag && matches
        ? new Response(null, { status: 304, headers: response.headers }) : response;
}
export async function publicResponse(request: Request, response: Response, now: string): Promise<Response> {
    response.headers.set("Cache-Control", "no-store");
    if (!publicRead(request) || response.status !== 200) return response;
    const text = await response.text();
    const body = object(JSON.parse(text));
    const checked = [body.checked_at, body.cve_checked_at, body.kev_checked_at]
        .filter((value) => value !== undefined);
    const milliseconds = Date.parse(now);
    const epss = new URL(request.url).pathname.startsWith("/v1/epss/");
    if (epss && body.status === "unavailable")
        return new Response(text, { status: response.status, headers: response.headers });
    const freshness = epss ? 6 * 60 * 60_000 : 30 * 60_000;
    let ttl = checked.length ? 60 : 0;
    for (const value of checked) {
        const at = typeof value === "string" ? Date.parse(value) : NaN;
        ttl = Math.min(ttl, Number.isFinite(at) && at <= milliseconds
            ? Math.max(0, Math.floor((at + freshness - milliseconds) / 1000)) : 0);
    }
    if (epss && body.status === "scored") {
        const day = object(body.score).date;
        const at = typeof day === "string" ? Date.parse(`${day}T00:00:00Z`) : NaN;
        ttl = Math.min(ttl, Number.isFinite(at) ? Math.max(0, Math.floor((at + 2 * 24 * 60 * 60_000 - milliseconds) / 1000)) : 0);
    }
    response.headers.set("ETag", `"${await sha256(text)}"`);
    if (ttl > 0) {
        response.headers.set("Cache-Control", `public, max-age=${ttl}, must-revalidate`);
        response.headers.set("Date", new Date(milliseconds).toUTCString());
        response.headers.set("Expires", new Date(milliseconds + ttl * 1000).toUTCString());
    }
    return conditional(request, new Response(text, { status: response.status, headers: response.headers }));
}

export async function cachedRead(
    request: Request, cache: Pick<Cache, "match" | "put">,
    load: (request: Request) => Promise<Response>, now = Date.now(),
): Promise<Response> {
    if (!publicRead(request)) return load(request);
    const key = new Request(request.url);
    const directives = request.headers.get("cache-control") ?? "";
    const noStore = /(?:^|,)\s*no-store\s*(?:,|$)/i.test(directives);
    const revalidate = noStore || /(?:^|,)\s*(?:no-cache|max-age\s*=\s*0)\s*(?:,|$)/i.test(directives) ||
        request.headers.get("pragma")?.toLowerCase() === "no-cache";
    if (!revalidate) {
        try {
            const hit = await cache.match(key);
            if (hit && Date.parse(hit.headers.get("Expires") ?? "") > now)
                return conditional(request, hit);
        } catch (error) {
            console.error("advisory_cache_read_failed", error);
        }
    }
    const response = await load(key);
    if (!noStore && response.status === 200 && response.headers.get("Cache-Control")?.startsWith("public,")) {
        try { await cache.put(key, response.clone()); }
        catch (error) { console.error("advisory_cache_write_failed", error); }
    }
    return conditional(request, response);
}
