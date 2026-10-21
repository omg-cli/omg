import type { CiBindings } from "@cloudflare/ci/worker";
import type { SentryBindings } from "./sentry-intake";

export type Env = CiBindings & Omit<SentryBindings, "BACKUP_BUCKET"> & {
  CI_API_TOKEN: string;
  CI_IMAGE_DIGEST: string;
  CI_VERIFIER_REVISION: string;
};
