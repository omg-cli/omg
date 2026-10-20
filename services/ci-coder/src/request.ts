import { z } from "zod";
import { createHash } from "node:crypto";
import {
  sourceReviewInputSchema,
  sourceReviewProposalSchema,
  validateReviewProposal,
  verifySourceBlobs,
} from "../../ci-inspector/src/review-contract";

const runNumber = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/)
  .refine((value) => Number.isSafeInteger(Number(value)));

export const codingRequestSchema = z
  .strictObject({
    repository: z.literal("omg-cli/omg"),
    sha: z.string().regex(/^[a-f0-9]{40}$/),
    branch: z.literal("main"),
    runId: runNumber,
    attempt: z.string().regex(/^[1-9][0-9]{0,5}$/),
    source: sourceReviewInputSchema,
    hypothesis: sourceReviewProposalSchema.optional(),
    candidateIndex: z.number().int().min(0).max(2).optional(),
  })
  .refine(
    (request) =>
      request.source.repository === request.repository &&
      request.source.sha === request.sha &&
      request.source.branch === request.branch,
    "Source identity mismatch",
  )
  .superRefine((request, context) => {
    if (request.hypothesis?.kind === "candidates") {
      if (
        request.candidateIndex === undefined ||
        request.candidateIndex >= request.hypothesis.candidates.length
      )
        context.addIssue({
          code: "custom",
          path: ["candidateIndex"],
          message: "An existing hypothesis candidate must be selected",
        });
    } else if (request.candidateIndex !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["candidateIndex"],
        message: "Candidate selection requires a candidate hypothesis",
      });
    }

    if (!request.hypothesis) return;

    try {
      validateReviewProposal(request.source, request.hypothesis);
    } catch {
      context.addIssue({
        code: "custom",
        path: ["hypothesis"],
        message: "Hypothesis evidence does not match the source snapshot",
      });
    }
  })
  .refine(
    (request) => new TextEncoder().encode(JSON.stringify(request)).length <= 512 * 1024,
    "Source snapshot exceeds 512 KiB",
  );

export type CodingRequest = z.infer<typeof codingRequestSchema>;

export const parseCodingRequest = codingRequestSchema.parse.bind(codingRequestSchema);

export const operationIdentity = (request: CodingRequest) => {
  const digest = createHash("sha256")
    .update(
      JSON.stringify({
        source: request.source,
        hypothesis: request.hypothesis ?? null,
        candidateIndex: request.candidateIndex ?? null,
      }),
    )
    .digest("hex");

  return `cl-${request.runId}-${request.attempt}-${request.sha}-s-${digest}`;
};

export function storedOperationIdentity(name: string | undefined, request: CodingRequest) {
  if (
    !name ||
    !/^cl-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}-[a-f0-9]{40}-s-[a-f0-9]{64}$/.test(name) ||
    !name.startsWith(`cl-${request.runId}-${request.attempt}-${request.sha}-s-`)
  )
    throw new Error("Named durable operation identity mismatch");

  return name;
}

export type ApiBindings = {
  CODER_API_TOKEN: string;
  CODER: {
    getByName(name: string): {
      start(request: CodingRequest): Promise<{ id: string; accepted: boolean; conflict?: boolean }>;
      status(): Promise<{ id: string; status: string }>;
    };
  };
};

const respond = <T>(value: T, status = 200) =>
  Response.json(value, { status, headers: { "Cache-Control": "no-store" } });

async function isAuthorized(request: Request, secret: string) {
  if (!secret) return false;

  const hashes = await Promise.all(
    [request.headers.get("Authorization") ?? "", `Bearer ${secret}`].map((value) =>
      crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  );

  const actual = new Uint8Array(hashes[0]);
  const expected = new Uint8Array(hashes[1]);
  let difference = 0;

  for (let index = 0; index < actual.length; index++) difference |= actual[index] ^ expected[index];

  return difference === 0;
}

export async function handleCoderRequest(
  request: Request,
  env: ApiBindings,
  assertReady: () => void | Promise<void>,
): Promise<Response> {
  if (!(await isAuthorized(request, env.CODER_API_TOKEN)))
    return respond({ error: "Unauthorized" }, 401);
  const pathname = new URL(request.url).pathname;

  try {
    if (pathname === "/operations" && request.method === "POST") {
      const reader = request.body?.getReader();

      if (!reader) return respond({ error: "Missing coding request" }, 400);
      const chunks: Uint8Array[] = [];
      let size = 0;

      try {
        for (;;) {
          const chunk = await reader.read();

          if (chunk.done) break;
          size += chunk.value.byteLength;

          if (size > 512 * 1024) {
            await reader.cancel();

            return respond({ error: "Coding request exceeds 512 KiB" }, 413);
          }

          chunks.push(chunk.value);
        }
      } finally {
        reader.releaseLock();
      }

      const bytes = new Uint8Array(size);
      let offset = 0;

      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.length;
      }

      let input;

      try {
        input = parseCodingRequest(
          JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
        );
      } catch {
        return respond({ error: "Invalid coding request" }, 400);
      }

      if (!(await verifySourceBlobs(input.source)))
        return respond({ error: "Source blob hash mismatch" }, 400);
      await assertReady();
      const id = operationIdentity(input);
      const result = await env.CODER.getByName(id).start(input);

      if (result.conflict) return respond({ error: "Operation identity conflict" }, 409);

      if (result.id !== id) throw new Error("Durable operation identity mismatch");

      return respond({ id, accepted: result.accepted, statusUrl: `/operations/${id}` }, 202);
    }

    const match =
      /^\/operations\/(cl-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}-[a-f0-9]{40}-s-[a-f0-9]{64})$/.exec(
        pathname,
      );

    if (!match || request.method !== "GET") return respond({ error: "Not found" }, 404);
    const result = await env.CODER.getByName(match[1]).status();

    if (result.id !== match[1]) return respond({ error: "Not found" }, 404);

    return respond(result);
  } catch {
    return respond({ error: "Coding service unavailable" }, 503);
  }
}
