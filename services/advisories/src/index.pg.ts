import { handle } from "./service";
import { refresh } from "./ingestion";
import { Store, d1Sql, type Sql } from "./storage";
import { pgSql } from "./pg";
import { cachedRead } from "./cache";
import { r2Raw } from "./raw-pack";

type Environment = Omit<Env, "DB_BACKEND" | "HYPERDRIVE"> & {
    INGEST_TOKEN?: string;
    RUNTIME_REFRESH_SECRET?: string;
    HYPERDRIVE?: Hyperdrive;
    HYPERDRIVE_REPLICA?: Hyperdrive;
    DB_BACKEND?: string;
};

function normalizeAdvisoryRoute(pathname: string): string {
    if (/^\/v1\/cves\/CVE-\d{4}-\d+$/i.test(pathname)) return "/v1/cves/:id";
    if (/^\/v1\/epss\/CVE-\d{4}-\d+$/i.test(pathname)) return "/v1/epss/:id";
    if (/^\/v1\/runtimes\/[a-z]+$/i.test(pathname)) return "/v1/runtimes/:name";
    if (/^\/v1\/eol\/[a-z0-9-]+$/i.test(pathname)) return "/v1/eol/:product";
    return pathname.slice(0, 64);
}

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

function openSql(
    env: Environment,
    route: string,
    preferReplica: boolean,
): { sql: Sql; close?: () => Promise<void> } {
    if (env.DB_BACKEND !== "d1") {
        if (preferReplica && env.HYPERDRIVE_REPLICA) {
            const pg = pgSql(env.HYPERDRIVE_REPLICA.connectionString, {
                application: "omg-advisories",
                route,
                target: "replica",
            });
            return { sql: pg, close: () => pg.close() };
        }
        if (env.HYPERDRIVE) {
            const pg = pgSql(env.HYPERDRIVE.connectionString, {
                application: "omg-advisories",
                route,
                target: "primary",
            });
            return { sql: pg, close: () => pg.close() };
        }
    }
    return { sql: d1Sql(env.DB) };
}

export default {
    fetch(request, env, context) {
        return cachedRead(
            request,
            caches.default,
            async (input) => {
                const route = normalizeAdvisoryRoute(new URL(input.url).pathname);
                const { sql, close } = openSql(env, route, isReplicaSafeRead(input));
                try {
                    return await handle(
                        input,
                        new Store(sql, r2Raw(env.RAW)),
                        env.INGEST_TOKEN,
                        new Date().toISOString(),
                        undefined,
                        env.RUNTIME_REFRESH_SECRET,
                    );
                } finally {
                    if (close) context.waitUntil(close());
                }
            },
            Date.now(),
            (promise) => context.waitUntil(promise),
        );
    },
    scheduled(_event, env, context) {
        context.waitUntil(
            (async () => {
                const { sql, close } = openSql(env, "cron:refresh", false);
                try {
                    await refresh(
                        new Store(sql, r2Raw(env.RAW)),
                        (url, init) => fetch(url, init),
                        new Date().toISOString(),
                        Number(env.CVE_BATCH_SIZE),
                    );
                } finally {
                    if (close) await close();
                }
            })(),
        );
    },
} satisfies ExportedHandler<Environment>;
