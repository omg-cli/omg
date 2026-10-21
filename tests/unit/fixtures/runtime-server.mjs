import { createHmac } from "node:crypto";
import { fetchCi } from "../../../services/cloud-ci/src/http.ts";
import { parseStart, runIdentity, requestKey, receiptKey } from "../../../services/cloud-ci/src/contract.ts";

export function runtimeServer() {
    const objects = new Map();
    const requests = [];
    const nativeStates = new Map();
    const env = {
        CI_API_TOKEN: "fixture-private-ci-token-32-characters",
        SENTRY_WEBHOOK_SECRET: "fixture-private-sentry-secret-32-characters",
        SENTRY_ORG_SLUG: "omg-org", SENTRY_PROJECT_SLUG: "omg", SENTRY_PROJECT_ID: "789", SENTRY_ENVIRONMENT: "production",
        BACKUP_BUCKET: {
            async delete(key) { objects.delete(key); },
            async list({ prefix, limit, cursor }) {
                const keys = [...objects.keys()].filter((key) => key.startsWith(prefix) && (!cursor || key > cursor)).sort();
                const selected = keys.slice(0, limit);
                const truncated = selected.length < keys.length;
                return { objects: selected.map((key) => ({ key })), truncated, ...(truncated ? { cursor: selected.at(-1) } : {}) };
            },
            async get(key) {
                const value = objects.get(key);
                return value === undefined ? null : { text: async () => value, body: value, etag: value };
            },
            async put(key, value, options) {
                const condition = options?.onlyIf;
                if (condition?.etagDoesNotMatch === "*" && objects.has(key)) return null;
                if (condition?.etagMatches !== undefined && condition.etagMatches !== objects.get(key)) return null;
                objects.set(key, value);
                return {};
            },
        },
        ARTIFACTS: { async get() { throw new Error("Unexpected native artifact access"); } },
        CI_WORKFLOW: {
            async create() { throw new Error("Unexpected native workflow start"); },
            async get(id) {
                if (!nativeStates.has(id)) throw new Error("Unexpected native workflow status");
                return { status: async () => ({ status: nativeStates.get(id) }) };
            },
        },
    };
    const endpoint = "https://omg-cloud-ci.latham.workers.dev/";
    return {
        env, objects, requests, endpoint, token: env.CI_API_TOKEN,
        stageNativeProof(value, receipt) {
            const request = parseStart(value);
            const id = runIdentity(request);
            objects.set(requestKey(id), JSON.stringify(request));
            objects.set(receiptKey(request), JSON.stringify(receipt));
            nativeStates.set(id, "complete");
            return id;
        },
        async request(url, token, body) {
            requests.push({ path: new URL(url).pathname, method: body ? "POST" : "GET" });
            const response = await fetchCi(new Request(url, {
                method: body ? "POST" : "GET", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
                ...(body ? { body } : {}),
            }), env);
            if (!response.ok) throw Object.assign(new Error(`Service request failed: HTTP ${response.status}.`), { status: response.status });
            return response.json();
        },
        async signedSend(payload) {
            const body = JSON.stringify(payload);
            return fetchCi(new Request(new URL("/sentry/events", endpoint), {
                method: "POST", body, headers: { "Content-Type": "application/json", "Sentry-Hook-Resource": "event_alert",
                    "Sentry-Hook-Signature": createHmac("sha256", env.SENTRY_WEBHOOK_SECRET).update(body).digest("hex") },
            }), env);
        },
    };
}
