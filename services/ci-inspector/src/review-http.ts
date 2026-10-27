import {
  sourceReviewInputSchema,
  validateReviewProposal,
  verifySourceBlobs,
  type SourceReviewInput,
  type SourceReviewProposal,
  SourceReviewFailure,
} from "./review-contract";
import { authorized, readBoundedJson, type InspectionRequest } from "./http";

export type ReviewInference = {
  proposal: SourceReviewProposal;
  model: string;
  usage: unknown;
  codeExecutions: number;
  sourceToolCalls: number;
  readPaths: string[];
  readDiff: boolean;
  readCiFailures?: number[];
};

type SourceReviewCandidate = Extract<
  SourceReviewProposal,
  { kind: "candidates" }
>["candidates"][number] & { verification: "uncorroborated" };

export type SourceReviewResponse = Pick<SourceReviewInput, "repository" | "sha" | "branch"> & {
  suppliedPaths: string[];
} & Omit<ReviewInference, "proposal"> & { publication: "requires-verifier" } & (
    | Extract<SourceReviewProposal, { kind: "no-findings" }>
    | { kind: "candidates"; summary: string; candidates: SourceReviewCandidate[] }
  );

export async function handleSourceReview(
  request: InspectionRequest,
  env: { CI_INSPECTOR_TOKEN: string },
  review: (input: SourceReviewInput) => Promise<ReviewInference>,
): Promise<Response> {
  const respond = (data: Parameters<typeof Response.json>[0], status = 200) =>
    Response.json(data, { status, headers: { "cache-control": "no-store" } });

  if (new URL(request.url).pathname !== "/review") return respond({ error: "Not found" }, 404);

  if (request.method !== "POST") return respond({ error: "Method not allowed" }, 405);

  if (!(await authorized(request, env.CI_INSPECTOR_TOKEN)))
    return respond({ error: "Unauthorized" }, 401);

  if (!request.headers.get("content-type")?.startsWith("application/json"))
    return respond({ error: "Expected application/json" }, 415);

  const body = await readBoundedJson(request, 512 * 1024);

  if (body.kind === "error") return respond({ error: body.error }, body.status);

  const parsed = sourceReviewInputSchema.safeParse(body.value);

  if (!parsed.success) return respond({ error: "Invalid source review" }, 400);

  const input = parsed.data;

  if (!(await verifySourceBlobs(input)))
    return respond({ error: "Source blob hash mismatch" }, 400);

  try {
    const result = await review(input);

    if (result.codeExecutions < 1 || result.sourceToolCalls < 1)
      throw new Error("Source tools were not executed");

    const suppliedPaths = input.sourceFiles.map((file) => file.path);
    const failureReads = result.readCiFailures ?? [];
    if (!Array.isArray(failureReads) || failureReads.length !== input.ciFailures.length ||
      new Set(failureReads).size !== failureReads.length ||
      failureReads.some(index => !Number.isSafeInteger(index) || index < 0 || index >= input.ciFailures.length))
      throw new Error("Invalid failure evidence read receipt");

    if (
      result.readPaths.length < 1 ||
      new Set(result.readPaths).size !== result.readPaths.length ||
      result.readPaths.some((path) => !suppliedPaths.includes(path))
    )
      throw new Error("Invalid source read receipt");

    const proposal = validateReviewProposal(input, result.proposal);

    if (
      proposal.kind === "candidates" &&
      proposal.candidates.some((candidate) =>
        candidate.evidence.some((evidence) => !result.readPaths.includes(evidence.path)),
      )
    )
      throw new Error("Evidence source was not read");

    const output =
      proposal.kind === "candidates"
        ? {
            ...proposal,
            candidates: proposal.candidates.map(
              (candidate) =>
                ({
                  ...candidate,
                  verification: "uncorroborated",
                }) satisfies SourceReviewCandidate,
            ),
          }
        : proposal;

    const response = {
      repository: input.repository,
      sha: input.sha,
      branch: input.branch,
      ...output,
      publication: "requires-verifier",
      model: result.model,
      usage: result.usage,
      codeExecutions: result.codeExecutions,
      sourceToolCalls: result.sourceToolCalls,
      suppliedPaths,
      readPaths: result.readPaths,
      readDiff: result.readDiff,
      readCiFailures: failureReads,
    } satisfies SourceReviewResponse;

    if (JSON.stringify(response).length > 100000) throw new Error("Review output too large");

    return respond(response);
  } catch (cause) {
    return respond(
      {
        error: "Source review failed",
        code: cause instanceof SourceReviewFailure ? cause.code : "REVIEW_REJECTED",
      },
      502,
    );
  }
}
