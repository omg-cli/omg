import { r2Raw } from "../src/raw-pack";

export default {
    async fetch(request: Request, environment: { RAW: R2Bucket }): Promise<Response> {
        try {
            const key = new URL(request.url).searchParams.get("key");
            if (key === null) throw new Error("missing fixture object key");
            const raw = await r2Raw(environment.RAW).get(key);
            return Response.json({text: raw ? await raw.text() : null});
        } catch (error) {
            return Response.json({error: error instanceof Error ? error.message : "unexpected fixture failure"}, {status:500});
        }
    },
};
