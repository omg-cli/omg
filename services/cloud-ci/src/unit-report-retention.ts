import type { CiSandbox } from "@cloudflare/ci/worker";
import type * as Workers from "@cloudflare/workers-types/index.ts";

export async function retainUnitReport(
  runId: string,
  sandbox: Pick<CiSandbox, "listFiles"> & {
    readReport(): Promise<Workers.ReadableStream<Uint8Array>>;
  },
  bucket: Pick<R2Bucket, "put">,
): Promise<"saved" | "invalid-identity" | "missing" | "unsafe" | "oversized" | "unavailable"> {
  if (!/^cl-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}-[a-f0-9]{40}(?:-v-[a-f0-9]{16})?$/.test(runId))
    return "invalid-identity";

  try {
    const listing = await sandbox.listFiles("/tmp/omg-ci-unit-evidence");

    if (!listing.success) return "unavailable";

    const file = listing.files.find(
      (entry) => entry.absolutePath === "/tmp/omg-ci-unit-evidence/report.xml",
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

      await bucket.put(`reports/${runId}/portable-units.xml`, body, {
        httpMetadata: { contentType: "application/xml" },
      });

      return "saved";
    } finally {
      await reader.cancel().catch(() => {});
    }
  } catch {
    return "unavailable";
  }
}
