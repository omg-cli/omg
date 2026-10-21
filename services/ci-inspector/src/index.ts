import { handleInspection } from "./http";
import { inspectSnapshot, type InspectorEnv } from "./inspect";
import { handleSourceReview } from "./review-http";
import { handlePatchReview } from "./patch-review-http";
import { reviewPatch, reviewSource } from "./review";
import type {
  ExportedHandler,
  Request,
  Response as WorkerResponse,
} from "@cloudflare/workers-types/index.ts";

function isWorkerResponse(response: Response): response is Response & WorkerResponse {
  return response instanceof Response && (response.type === "default" || response.type === "error");
}

export default {
  async fetch(request: Request, env: InspectorEnv) {
    const response =
      new URL(request.url).pathname === "/patch-review"
        ? await handlePatchReview(request, env, (input) => reviewPatch(input, env))
        : new URL(request.url).pathname === "/review"
        ? await handleSourceReview(request, env, (input) => reviewSource(input, env))
        : await handleInspection(request, env, (snapshot) => inspectSnapshot(snapshot, env));

    if (!isWorkerResponse(response)) throw new Error("Unsupported Worker response type");

    return response;
  },
} satisfies ExportedHandler<InspectorEnv>;
