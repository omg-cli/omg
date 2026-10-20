import type { CiBindings } from "@cloudflare/ci/worker";

export type Env = CiBindings & {
  CI_API_TOKEN: string;
  CI_IMAGE_DIGEST: string;
  CI_VERIFIER_REVISION: string;
};
