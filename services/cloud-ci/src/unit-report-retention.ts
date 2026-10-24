import type { CiSandbox } from "@cloudflare/ci/worker";
import type * as Workers from "@cloudflare/workers-types/index.ts";
import { cloudCiChecks } from "../runner/plan.mjs";

type EvidenceSource = Pick<CiSandbox, "listFiles"> & {
  readReport(): Promise<Workers.ReadableStream<Uint8Array>>;
};
export type RetentionStatus =
  | "saved"
  | "invalid-identity"
  | "missing"
  | "unsafe"
  | "oversized"
  | "unavailable";
export const runIdPattern = /^cl-[1-9][0-9]{0,19}-[1-9][0-9]{0,5}-[a-f0-9]{40}(?:-(?:v|ta)-[a-f0-9]{16})?$/;

const baseRunId = (runId: string) => runId.replace(/-(?:v|ta)-[a-f0-9]{16}$/, "");
export const runIdMatchesOwner = (runId: string, owner: string) => baseRunId(runId) === baseRunId(owner);

export async function retainUnitReport(
  runId: string,
  sandbox: EvidenceSource,
  bucket: Pick<R2Bucket, "put">,
): Promise<RetentionStatus> {
  if (!runIdPattern.test(runId)) return "invalid-identity";

  let parent: Awaited<ReturnType<EvidenceSource["listFiles"]>>;

  try {
    parent = await sandbox.listFiles("/tmp");
  } catch {
    return "unavailable";
  }

  if (
    !parent.success ||
    !Array.isArray(parent.files) ||
    parent.count !== parent.files.length
  )
    return "unavailable";

  const directory = parent.files.find(
    (entry) => entry.absolutePath === "/tmp/omg-ci-unit-evidence",
  );

  if (!directory) return "missing";

  if (directory.type !== "directory") return "unsafe";

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

export type SandboxEvidenceMetadata = {
  reportRunId?: string;
  diagnosticRunId?: string;
  leafStep?: string;
};

export type EvidenceFailure = { evidence: string; status: RetentionStatus };

const blocksRelease = (status: RetentionStatus, required: boolean) =>
  status === "unsafe" ||
  status === "unavailable" ||
  status === "oversized" ||
  status === "invalid-identity" ||
  (required && status === "missing");

export async function retainSandboxEvidence(
  metadata: SandboxEvidenceMetadata | undefined,
  sandbox: Pick<CiSandbox, "listFiles">,
  read: (path: string) => Promise<Workers.ReadableStream<Uint8Array>>,
  bucket: Pick<R2Bucket, "put">,
  owner?: string,
): Promise<{ retained: boolean; failures: EvidenceFailure[] }> {
  const failures: EvidenceFailure[] = [];

  if (metadata?.diagnosticRunId && !metadata.leafStep)
    failures.push({ evidence: "runner-log:leaf-step", status: "missing" });

  if (metadata?.diagnosticRunId && metadata.leafStep) {
    for (const stream of ["stdout", "stderr"] as const) {
      const status = await retainRunnerLog(
        metadata.diagnosticRunId,
        metadata.leafStep,
        stream,
        {
          listFiles: (path) => sandbox.listFiles(path),
          readReport: () => read(`/tmp/ci-step.${stream === "stdout" ? "out" : "err"}`),
        },
        bucket,
      );

      if (blocksRelease(status, true)) failures.push({ evidence: `runner-log:${stream}`, status });
    }
  }

  if (metadata?.reportRunId) {
    const status =
      owner && !runIdMatchesOwner(metadata.reportRunId, owner)
        ? "invalid-identity"
        : await retainUnitReport(
            metadata.reportRunId,
            {
              listFiles: (path) => sandbox.listFiles(path),
              readReport: () => read("/tmp/omg-ci-unit-evidence/report.xml"),
            },
            bucket,
          );

    if (blocksRelease(status, false)) failures.push({ evidence: "unit-report", status });
  }

  return { retained: failures.length === 0, failures };
}

const terminalStatuses = new Set(["complete", "errored", "terminated"]);

export type TerminalOwnerResult =
  | "released"
  | "retained-active"
  | "retained-owner-changed"
  | "missing-owner"
  | "invalid-owner"
  | "mismatched-owner";

export async function releaseTerminalOwner(options: {
  readOwner: () => Promise<string | undefined>;
  lookup: (owner: string) => Promise<{ id: string; status: string }>;
  retain: (owner: string) => Promise<{ retained: boolean; failures: EvidenceFailure[] }>;
  acquire?: (owner: string) => void | Promise<void>;
  release?: () => void;
  destroy: () => Promise<void>;
  delegate: () => Promise<void>;
  warn: (event: Record<string, unknown>) => void;
}): Promise<TerminalOwnerResult> {
  const owner = await options.readOwner();

  if (!owner) {
    options.warn({ event: "sandbox_owner_missing" });
    await options.delegate();

    return "missing-owner";
  }

  if (!runIdPattern.test(owner)) {
    options.warn({ event: "sandbox_owner_invalid" });
    await options.delegate();

    return "invalid-owner";
  }

  const instance = await options.lookup(owner);

  if (instance.id !== owner) {
    options.warn({ event: "sandbox_owner_mismatch", owner, instanceId: instance.id });
    await options.delegate();

    return "mismatched-owner";
  }

  if (!terminalStatuses.has(instance.status)) {
    await options.delegate();

    return "retained-active";
  }

  await options.acquire?.(owner);

  try {
    const claimedOwner = await options.readOwner();

    if (claimedOwner !== owner) {
      options.warn({ event: "sandbox_owner_changed", owner, durableOwner: claimedOwner });
      await options.delegate();

      return "retained-owner-changed";
    }

    const retention = await options.retain(owner);

    if (!retention.retained) {
      options.warn({ event: "sandbox_evidence_retention_failed", owner, failures: retention.failures });
      throw new Error(
        `Sandbox evidence retention failed: ${retention.failures
          .map((failure) => `${failure.evidence}:${failure.status}`)
          .join(",")}`,
      );
    }

    await options.destroy();

    return "released";
  } finally {
    options.release?.();
  }
}
