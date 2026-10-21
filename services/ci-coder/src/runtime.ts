import { z } from "zod";
import type { Env } from "./env.js";

export const CODING_MODEL = "@cf/deepseek-ai/deepseek-v4.1-flash-1017";

const identitySchema = z.strictObject({
  bundleSha256: z.string().regex(/^[a-f0-9]{64}$/),
  imageDigest: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  verifierRevision: z.string().regex(/^[a-f0-9]{40}$/),
  model: z.literal(CODING_MODEL),
  reasoningEffort: z.literal("high"),
});

export function codingRuntimeIdentity(
  configuration: Pick<Env, "CI_API_TOKEN" | "CI_IMAGE_DIGEST" | "CI_VERIFIER_REVISION">,
  bundleSha256: string,
) {
  if (configuration.CI_API_TOKEN.length < 32 || /\s/.test(configuration.CI_API_TOKEN))
    throw new Error("Trusted verifier credential is required");

  return identitySchema.parse({
    bundleSha256,
    imageDigest: configuration.CI_IMAGE_DIGEST,
    verifierRevision: configuration.CI_VERIFIER_REVISION,
    model: CODING_MODEL,
    reasoningEffort: "high",
  });
}

export function assertRuntimeIdentity(
  previous: string | undefined,
  current: z.infer<typeof identitySchema>,
) {
  if (
    previous &&
    JSON.stringify(identitySchema.parse(JSON.parse(previous))) !== JSON.stringify(current)
  )
    throw new Error("Operation runtime identity changed during recovery");
}

export const parseRuntimeIdentity = (text: string) => identitySchema.parse(JSON.parse(text));

export function diagnosticFailureMetadata(
  message: { finish?: string; error?: { type: string; message: string; status?: number } },
  secrets: readonly string[],
) {
  let error = message.error?.message;
  if (error !== undefined) {
    for (const secret of secrets) if (secret) error = error.replaceAll(secret, "[REDACTED]");
    error = error.replace(/Bearer\s+\S+/gi, "Bearer [REDACTED]").slice(0, 2000);
  }
  return {
    finish: message.finish,
    error: message.error ? {type: message.error.type, status: message.error.status, message: error} : undefined,
  };
}

export const RATE_LIMIT_RETRY_DELAY_MS = 60_000;

export type SessionRetryEvent = {
  attempt: number;
  error: { type: string; message: string; status?: number };
};

export function retryDecision(
  event: SessionRetryEvent,
): { retry: false } | { retry: true; delay: number } | null {
  if (event.attempt >= 2) return { retry: false };
  if (event.error.status === 429)
    return { retry: true, delay: RATE_LIMIT_RETRY_DELAY_MS };
  if (event.error.status === undefined && /rate limit/i.test(event.error.message))
    return { retry: true, delay: RATE_LIMIT_RETRY_DELAY_MS };
  return null;
}
