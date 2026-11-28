import { handle } from "./service";
import { refresh } from "./ingestion";
import { Store, d1ReadSql, d1WriteSql } from "./storage";
import { cachedRead } from "./cache";
import { r2Raw } from "./raw-pack";

type Environment = Env & { INGEST_TOKEN?: string; RUNTIME_REFRESH_SECRET?: string };

function isReplicaSafeRead(request: Request): boolean {
    const pathname = new URL(request.url).pathname;
    if (request.method === "POST" && pathname === "/v1/packages/audit") return true;
    if (request.method !== "GET") return false;
    return (
        pathname === "/v1/status" ||
        pathname === "/v1/arch/advisories" ||
        pathname === "/v1/bundles/hot" ||
        pathname === "/v1/packages/check" ||
        pathname === "/v1/eol" ||
        /^\/v1\/eol\/[a-z0-9-]+$/.test(pathname) ||
        pathname === "/v1/cves/recent" ||
        /^\/v1\/cves\/CVE-\d{4}-\d{4,19}$/.test(pathname)
    );
}

export default {
    fetch(request, env, context) {
        return cachedRead(
            request,
            caches.default,
            (input) => {
                const sql = isReplicaSafeRead(input) ? d1ReadSql(env.DB) : d1WriteSql(env.DB);
                return handle(
                    input,
                    new Store(sql, r2Raw(env.RAW)),
                    env.INGEST_TOKEN,
                    new Date().toISOString(),
                    undefined,
                    env.RUNTIME_REFRESH_SECRET,
                );
            },
            Date.now(),
            (promise) => context.waitUntil(promise),
        );
    },
    scheduled(_event, env, context) {
        context.waitUntil(
            refresh(
                new Store(d1WriteSql(env.DB), r2Raw(env.RAW)),
                (url, init) => fetch(url, init),
                new Date().toISOString(),
                Number(env.CVE_BATCH_SIZE),
            ),
        );
    },
} satisfies ExportedHandler<Environment>;
