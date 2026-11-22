export const STAGE_ORIGIN = "https://omg-advisories-stage-20261121-1d6c61c4.latham.workers.dev";
export const CANONICAL_ORIGIN = "https://omg-advisories.latham.workers.dev";
export const STAGE_MODE = "isolated-baseline-v1";

export const BASELINE_PATHS = new Set([
    "/internal/baseline/start", "/internal/ingest", "/internal/baseline", "/internal/baseline/verify",
]);
export const STAGE_POST_PATHS = new Set([
    ...BASELINE_PATHS, "/internal/cve-refresh", "/internal/runtime-refresh",
]);
