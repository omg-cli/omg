import type { CiSandbox } from "@cloudflare/ci/worker";
import type * as Workers from "@cloudflare/workers-types/index.ts";
import { cloudCiChecks } from "../runner/plan.mjs";

type EvidenceSource = Pick<CiSandbox, "listFiles"> & {
  readReport(): Promise<Workers.ReadableStream<Uint8Array>>;
};
type RetentionStatus =
  | "saved"
  | "invalid-identity"
  | "missing"
  | "unsafe"
  | "oversized"
  | "unavailable";
const runIdPattern = /^cl-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}-[a-f0-9]{40}(?:-(?:v|ta)-[a-f0-9]{16})?$/;

export async function retainUnitReport(
  runId: string,
  sandbox: EvidenceSource,
  bucket: Pick<R2Bucket, "put">,
): Promise<RetentionStatus> {
  if (!runIdPattern.test(runId)) return "invalid-identity";
  return retainFile({
    directory: "/tmp/omg-ci-unit-evidence",
    file: "/tmp/omg-ci-unit-evidence/report.xml",
    key: `reports/${runId}/portable-units.xml`,
    contentType: "application/xml",
  }, sandbox, bucket);
}

export async function retainRunnerLog(
  runId: string,
  step: string,
  stream: string,
  sandbox: EvidenceSource,
  bucket: Pick<R2Bucket, "put">,
): Promise<RetentionStatus> {
  if (
    !runIdPattern.test(runId) ||
    ![...cloudCiChecks, "regression-red-green", "test-audit-four-state", "test-audit-sensitivity"].includes(step) ||
    (stream !== "stdout" && stream !== "stderr")
  ) return "invalid-identity";
  return retainFile({
    directory: "/tmp",
    file: `/tmp/ci-step.${stream === "stdout" ? "out" : "err"}`,
    key: `diagnostics/runner-logs/${runId}/${step}.${stream}`,
    contentType: "text/plain; charset=utf-8",
  }, sandbox, bucket);
}

async function retainFile(
  paths: { directory: string; file: string; key: string; contentType: string },
  sandbox: EvidenceSource,
  bucket: Pick<R2Bucket, "put">,
): Promise<RetentionStatus> {
  try {
    const listing = await sandbox.listFiles(paths.directory);

    if (!listing.success) return "unavailable";

    const file = listing.files.find(
      (entry) => entry.absolutePath === paths.file,
    );

    if (!file) return "missing";

    if (file.type !== "file") return "unsafe";

    if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > 20_000_000)
      return "oversized";
    const source = await sandbox.readReport();
    const reader = source.getReader();
    const body = new Uint8Array(file.size);
    let bytes = 0;

    try {
      for (;;) {
        const chunk = await reader.read();

        if (chunk.done) {
          if (bytes !== file.size) return "unavailable";
          break;
        }

        const offset = bytes;
        bytes += chunk.value.byteLength;

        if (bytes > 20_000_000) return "oversized";

        if (bytes > file.size) return "unavailable";
        body.set(chunk.value, offset);
      }

      await bucket.put(paths.key, body, {
        httpMetadata: { contentType: paths.contentType },
      });

      return "saved";
    } finally {
      await reader.cancel().catch(() => {});
    }
  } catch {
    return "unavailable";
  }
}
