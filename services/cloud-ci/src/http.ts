import { z } from "zod";
import type * as Workers from "@cloudflare/workers-types/index.ts";
import { reviewRecords } from "./review-records";
import { diagnosticsHttp } from "./diagnostics-http";
import { receiveSentry, sentryRecords, type SentryBindings } from "./sentry-intake";
import { cloudCiChecks } from "../runner/plan.mjs";
import { testAuditReportNames } from "../runner/test-audit.mjs";
import {
    nativeParams,
    parseStart,
    receiptKey,
    requestKey,
    runIdentity,
    source,
    terminalSuccess,
} from "./contract";

type Request = globalThis.Request | Workers.Request;

type Response = Workers.Response;

function matchesRequest(text: string, input: ReturnType<typeof parseStart>) {
    try {
        return JSON.stringify(parseStart(JSON.parse(text))) === JSON.stringify(input);
    } catch {
        return false;
    }
}

declare const Response: typeof Workers.Response;

const json = <T>(value: T, status = 200) =>
    Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

type HttpBindings = Omit<SentryBindings, "BACKUP_BUCKET"> & {
    CI_API_TOKEN: string;
    ARTIFACTS: {
        get(name: string): Promise<{
            createToken(
                scope: "write",
                ttl: number,
            ): Promise<{ plaintext: string; id: string; expiresAt: string }>;
        }>;
    };
    BACKUP_BUCKET: {
        delete?(key: string): Promise<void>;
        list?(options: {
            prefix: string;
            limit: number;
            cursor?: string;
        }): Promise<{ objects: { key: string }[]; truncated: boolean; cursor?: string }>;
        get(key: string): Promise<{ text(): Promise<string>; body: Workers.BodyInit; etag?: string } | null>;
        put(key: string, value: string, options?: R2PutOptions): Promise<object | null>;
    };
    CI_WORKFLOW: {
        create(options: { id: string; params: ReturnType<typeof nativeParams> }): Promise<object>;
        get(id: string): Promise<{ status(): Promise<{ status: string }> }>;
    };
};

export async function fetchCi(request: Request, env: HttpBindings): Promise<Response> {
    if (new URL(request.url).pathname === "/sentry/events" && request.method === "POST")
        return receiveSentry(request, env);
    const authorization = request.headers.get("Authorization") ?? "";

    const hashes = await Promise.all(
        [authorization, `Bearer ${env.CI_API_TOKEN}`].map((value) =>
            crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
        ),
    );

    const actual = new Uint8Array(hashes[0]);
    const expected = new Uint8Array(hashes[1]);
    let difference = 0;

    for (let index = 0; index < actual.length; index++)
        difference |= actual[index] ^ expected[index];

    if (!env.CI_API_TOKEN || difference !== 0) return json({ error: "Unauthorized" }, 401);

    try {
        return await routeCi(request, env);
    } catch {
        return json({ error: "CI provider unavailable; retry the same request" }, 503);
    }
}

async function routeCi(request: Request, env: HttpBindings): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/sentry/poll" || url.pathname === "/sentry/events" || url.pathname.startsWith("/sentry/events/"))
        return sentryRecords(request, env.BACKUP_BUCKET);

    if (url.pathname.startsWith("/diagnostics/"))
        return diagnosticsHttp(request, env.BACKUP_BUCKET);

    if (url.pathname.startsWith("/review-records/"))
        return reviewRecords(request, env.BACKUP_BUCKET);

    if (url.pathname === "/health" && request.method === "GET")
        return json({ ok: true, engine: "@cloudflare/ci@0.2.0" });

    if (["/runs", "/source-token"].includes(url.pathname) && request.method === "POST") {
        let input;
        let document: unknown;
        let size = 0;

        try {
            const reader = request.body?.getReader();
            const chunks: Uint8Array[] = [];

            if (reader) {
                try {
                    while (true) {
                        const chunk = await reader.read();

                        if (chunk.done) break;
                        size += chunk.value.byteLength;

                        if (size > (url.pathname === "/source-token" ? 2048 : 1024 * 1024)) {
                            await reader.cancel();

                            return json({ error: "CI request too large" }, 413);
                        }

                        chunks.push(chunk.value);
                    }
                } finally {
                    reader.releaseLock();
                }
            }

            const bytes = new Uint8Array(size);
            let offset = 0;

            for (const chunk of chunks) {
                bytes.set(chunk, offset);
                offset += chunk.byteLength;
            }

            const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes);
            document = JSON.parse(text || (url.pathname === "/source-token" ? "{}" : "null"));

            if (url.pathname === "/runs") {
                input = parseStart(document);
                if (size > (input.testAudit ? 1024 * 1024 : 65536)) return json({ error: "CI request too large" }, 413);
            }
            else z.strictObject({}).parse(document);
        } catch {
            if (size > 65536) return json({ error: "CI request too large" }, 413);
            return json({ error: "Invalid CI request" }, 400);
        }

        if (url.pathname === "/source-token") {
            const repo = await env.ARTIFACTS.get(source.repo);
            const token = await repo.createToken("write", 300);

            return json({
                repository: source.repository,
                token: token.plaintext,
                id: token.id,
                expiresAt: token.expiresAt,
            });
        }

        if (!input) return json({ error: "Invalid CI request" }, 400);

        const id = runIdentity(input);
        const key = requestKey(id);
        let previous = await env.BACKUP_BUCKET.get(key);

        if (previous) {
            if (!matchesRequest(await previous.text(), input))
                return json({ error: "Run identity conflict" }, 409);
        } else {
            const written = await env.BACKUP_BUCKET.put(key, JSON.stringify(input), {
                onlyIf: { etagDoesNotMatch: "*" },
                httpMetadata: { contentType: "application/json" },
            });

            if (!written) {
                previous = await env.BACKUP_BUCKET.get(key);

                if (!previous)
                    return json({ error: "Run creation in progress; retry the same request" }, 409);

                if (!matchesRequest(await previous.text(), input))
                    return json({ error: "Run identity conflict" }, 409);
            }
        }

        try {
            await env.CI_WORKFLOW.create({ id, params: nativeParams(input) });
        } catch {
            const instance = await env.CI_WORKFLOW.get(id);
            await instance.status();
        }

        return json(
            { id, sha: input.sha, statusUrl: `/runs/${id}`, receiptUrl: `/runs/${id}/receipt` },
            202,
        );
    }

    const match =
        /^\/runs\/(cl-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}-[a-f0-9]{40}(?:-(?:v|ta)-[a-f0-9]{16})?)(?:\/(.*))?$/.exec(
            url.pathname,
        );

    if (!match || request.method !== "GET") return json({ error: "Not found" }, 404);
    const id = match[1];
    const object = await env.BACKUP_BUCKET.get(requestKey(id));

    if (!object) return json({ error: "Not found" }, 404);
    const input = parseStart(JSON.parse(await object.text()));
    const suffix = match[2];

    if (suffix?.startsWith("logs/")) {
        const name = suffix.slice(5);

        const allowed = new Set([
            "failure.txt",
            "regression-red-green.stdout",
            "regression-red-green.stderr",
            "test-audit-four-state.stdout",
            "test-audit-four-state.stderr",
            "test-audit-sensitivity.stdout",
            "test-audit-sensitivity.stderr",
            ...cloudCiChecks.flatMap((check) => [`${check}.stdout`, `${check}.stderr`]),
        ]);

        if (!allowed.has(name)) return json({ error: "Not found" }, 404);
        const log = await env.BACKUP_BUCKET.get(`logs/${id}/${name}`);

        return log
            ? new Response(log.body, {
                  headers: {
                      "Content-Type": "text/plain; charset=utf-8",
                      "Cache-Control": "no-store",
                  },
              })
            : json({ error: "Not found" }, 404);
    }

    if (suffix?.startsWith("reports/")) {
        const name = suffix.slice(8);

        if (
            ![
                "rust-pgp-license-junit.xml",
                "rust-debian-pure-junit.xml",

                "regression-baseline.json",
                "regression-patched.json",
                ...testAuditReportNames,
            ].includes(name)
        )
            return json({ error: "Not found" }, 404);
        const report = await env.BACKUP_BUCKET.get(`reports/${id}/${name}`);

        return report
            ? new Response(report.body, {
                  headers: {
                      "Content-Type": name.endsWith(".xml")
                          ? "application/xml"
                          : "application/json",
                      "Cache-Control": "no-store",
                  },
              })
            : json({ error: "Not found" }, 404);
    }

    if (suffix && !["receipt", "evidence"].includes(suffix))
        return json({ error: "Not found" }, 404);
    const state = await (await env.CI_WORKFLOW.get(id)).status();

    if (!suffix) return json({ id, ...input, status: state.status });
    const receipt = await env.BACKUP_BUCKET.get(receiptKey(input));

    if (!receipt)
        return json(
            { id, status: state.status, error: "Receipt unavailable" },
            terminalSuccess(state.status) ? 502 : 202,
        );

    if (suffix === "evidence") {
        if (!["complete", "errored", "terminated"].includes(state.status))
            return json({ id, status: state.status, error: "Workflow is not terminal" }, 202);

        return new Response(receipt.body, {
            headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
        });
    }

    if (!terminalSuccess(state.status))
        return json(
            { id, status: state.status, error: "Workflow has not completed successfully" },
            ["errored", "terminated"].includes(state.status) ? 422 : 202,
        );

    return new Response(receipt.body, {
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    });
}
