import type { Ai } from "@cloudflare/workers-types/index.ts";
import type { ApiBindings } from "./request.js";

export type { CodingRequest } from "./request.js";

export type Env = {
  AI: Ai;
  CODER: ApiBindings["CODER"];
  CI_SERVICE: { fetch(input: string, init?: RequestInit): Promise<Response> };
  CI_API_TOKEN: string;
  CODER_API_TOKEN: string;
  CI_IMAGE_DIGEST: string;
  CI_VERIFIER_REVISION: string;
};
