import { refresh, type Fetcher } from "./ingestion";
import { r2Raw } from "./raw-pack";
import { handle } from "./service";
import { BASELINE_PATHS, CANONICAL_ORIGIN, STAGE_MODE, STAGE_ORIGIN, STAGE_POST_PATHS } from "./stage-identity";
import { d1Sql, Store } from "./storage";

type StagePolicy = {
    STAGE_MODE?: string;
    STAGE_ACCESS_AUD?: string;
    STAGE_DATABASE_INSTANCE_ID?: string;
    STAGE_INGEST_TOKEN?: string;
    STAGE_RUNTIME_REFRESH_SECRET?: string;
};
type StageEnv = StagePolicy & Pick<Env, "DB" | "RAW"> & { STAGE_ENABLE_CRON?: string };

function configured(policy: StagePolicy) {
    const { STAGE_ACCESS_AUD: aud, STAGE_DATABASE_INSTANCE_ID: id, STAGE_INGEST_TOKEN: ingest, STAGE_RUNTIME_REFRESH_SECRET: proof } = policy;
    if (policy.STAGE_MODE !== STAGE_MODE || !id || !/^[a-f0-9]{32}$/.test(id) ||
        !aud || !/^[a-f0-9]{64}$/.test(aud) ||
        !ingest || !proof || ingest.length < 32 || proof.length < 32 || ingest === proof) return null;
    return { aud, id, ingest, proof };
}

async function isolated(store: Store, id: string) {
    const database = await store.sql.first<{id: string}>("SELECT id FROM database_instance");
    return database?.id === id && (await store.raw.get(`stage-isolation/${id}`)) !== null;
}

const unavailable = () => new Response(null, { status: 503, headers: { "Cache-Control": "no-store" } });

export async function handleStage(
    request: Request, access: Pick<ExecutionContext, "access">, policy: StagePolicy,
    makeStore: () => Store, now: string, fetcher?: Fetcher,
) {
    const url = new URL(request.url);
    if (url.origin !== STAGE_ORIGIN || !access.access) {
        return new Response(null, { status: 403, headers: { "Cache-Control": "no-store" } });
    }
    const options = configured(policy);
    if (!options) return unavailable();
    if (access.access.aud !== options.aud) {
        return new Response(null, { status: 403, headers: { "Cache-Control": "no-store" } });
    }
    if (!(request.method === "GET" && url.pathname.startsWith("/v1/")) &&
        !(request.method === "POST" && !url.search && STAGE_POST_PATHS.has(url.pathname))) {
        return new Response(null, { status: 404, headers: { "Cache-Control": "no-store" } });
    }
    const store = makeStore();
    try {
        if (!await isolated(store, options.id)) return unavailable();
    } catch {
        return unavailable();
    }
    const input = BASELINE_PATHS.has(url.pathname)
        ? new Request(new URL(url.pathname, CANONICAL_ORIGIN), {
            method: request.method, body: request.body,
            headers: {
                authorization: request.headers.get("authorization") ?? "",
                "content-type": request.headers.get("content-type") ?? "",
            },
        })
        : request;
    const response = await handle(input, store, options.ingest, now, fetcher, options.proof);
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", "no-store");
    return new Response(response.body, { status: response.status, headers });
}

export default {
    fetch(request, env, ctx) {
        return handleStage(request, ctx, env, () => new Store(d1Sql(env.DB), r2Raw(env.RAW)), new Date().toISOString());
    },
    async scheduled(_event, env) {
        if (env.STAGE_ENABLE_CRON !== "true") return;
        const options = configured(env);
        const store = new Store(d1Sql(env.DB), r2Raw(env.RAW));
        if (!options || !await isolated(store, options.id)) throw new Error("stage bindings not admitted");
        await refresh(store, (url, init) => fetch(url, init), new Date().toISOString(), 32);
    },
} satisfies ExportedHandler<StageEnv>;
