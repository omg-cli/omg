import { handle } from "./service";
import { refresh } from "./ingestion";
import { Store, d1Sql } from "./storage";
import { cachedRead } from "./cache";
type Environment = Env & { INGEST_TOKEN?: string };
export default {
    fetch(request, env) {
        return cachedRead(
            request, caches.default,
            (input) => handle(input, new Store(d1Sql(env.DB), env.RAW), env.INGEST_TOKEN),
        );
    },
    scheduled(_event, env, context) {
        context.waitUntil(
            refresh(
                new Store(d1Sql(env.DB), env.RAW),
                (url, init) => fetch(url, init),
                new Date().toISOString(),
                Number(env.CVE_BATCH_SIZE),
            ),
        );
    },
} satisfies ExportedHandler<Environment>;
