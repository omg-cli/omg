import type { OperatorFetcher } from "../advisories/scripts/operator";
import { object } from "../advisories/src/domain";
import { STAGE_ORIGIN, STAGE_POST_PATHS } from "./stage-identity";

export function stageOperatorFetcher(clientId: string | undefined, clientSecret: string | undefined, fetcher: OperatorFetcher = fetch): OperatorFetcher {
    if (!clientId || !clientSecret) throw new Error("stage Access credentials required");
    return async (input, init) => {
        if (!(input instanceof URL) || input.origin !== STAGE_ORIGIN || input.username || input.password ||
            input.search || input.hash || !STAGE_POST_PATHS.has(input.pathname) ||
            init?.method !== "POST" || init.redirect !== "error") throw new Error("stage credential destination refused");
        const headers = new Headers(init.headers);
        headers.set("CF-Access-Client-Id", clientId);
        headers.set("CF-Access-Client-Secret", clientSecret);
        const reply = await fetcher(input, { ...init, headers });
        if (reply.redirected || (reply.status >= 300 && reply.status < 400) || (reply.url && reply.url !== input.href)) {
            await reply.body?.cancel();
            throw new Error("stage redirect refused");
        }
        return reply;
    };
}

export function stageCheckpoint(value: unknown) {
    const saved = object(value);
    if (saved.transport_endpoint !== STAGE_ORIGIN) {
        throw new Error("checkpoint transport does not match operator mode");
    }
    return object(saved.checkpoint);
}
