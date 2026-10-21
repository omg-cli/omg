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
