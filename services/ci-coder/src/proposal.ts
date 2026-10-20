import { Schema } from "effect";
import { adaptReviewCandidate, gitBlobSha } from "../../../scripts/ai-review-candidate.mjs";
import { proposalDigest } from "../../../scripts/ai-review-publication.mjs";
import { verificationSchema } from "../../cloud-ci/src/verification-schema";
import {
  sourceReviewInputSchema,
  sourceReviewProposalSchema,
  validateReviewProposal,
  type SourceReviewInput,
  type SourceReviewProposal,
} from "../../ci-inspector/src/review-contract";

const requestSchema = Schema.Struct({
  repository: Schema.Literal("omg-cli/omg"),
  sha: Schema.String.check(Schema.isPattern(/^[a-f0-9]{40}$/)),
  branch: Schema.Literal("main"),
  runId: Schema.String.check(Schema.isPattern(/^[1-9][0-9]{0,19}$/)),
  attempt: Schema.String.check(Schema.isPattern(/^[1-9][0-9]{0,5}$/)),
  source: Schema.Unknown,
});

export type CoderProposalRequest = {
  repository: string;
  sha: string;
  branch: string;
  runId: string;
  attempt: string;
  source: SourceReviewInput;
};

export function createCoderProposal(
  request: CoderProposalRequest,
  candidate: SourceReviewProposal,
) {
  const identity = Schema.decodeUnknownSync(requestSchema, { onExcessProperty: "error" })(request);
  const source = sourceReviewInputSchema.parse(identity.source);

  if (
    identity.repository !== source.repository ||
    identity.sha !== source.sha ||
    identity.branch !== source.branch ||
    !Number.isSafeInteger(Number(identity.runId))
  )
    throw new Error("Coder request and source identity mismatch");

  const proposal = sourceReviewProposalSchema.parse(candidate);

  if (
    proposal.kind !== "candidates" ||
    proposal.candidates.length !== 1 ||
    !proposal.candidates[0].proposedFix
  )
    throw new Error("Coder must submit exactly one candidate with a proposed repair");

  validateReviewProposal(source, proposal);
  const sources = new Map<string, { sha: string; mode: "100644"; content: string }>();

  for (const file of source.sourceFiles) {
    if (gitBlobSha(file.content) !== file.blobSha)
      throw new Error("Coder source content differs from its Git blob identity");

    sources.set(file.path, { sha: file.blobSha, mode: "100644", content: file.content });
  }

  const adapted = adaptReviewCandidate({
    input: source,
    review: proposal,
    candidateIndex: 0,
    sources,
  });

  const normalized = verificationSchema.omit({ verifierRevision: true }).parse(adapted);

  return { ...normalized, proposalSha256: proposalDigest(normalized.proposal) };
}

export type CoderProposal = ReturnType<typeof createCoderProposal>;
