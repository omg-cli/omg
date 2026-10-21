import { expect, test } from "bun:test";
import type * as Workers from "@cloudflare/workers-types/index.ts";
import { retainRunnerLog, retainUnitReport } from "../src/unit-report-retention";
import { candidateReportStatus } from "../runner/unit-report-evidence.mjs";

declare const ReadableStream: typeof Workers.ReadableStream;
declare const Response: typeof Workers.Response;

const id = `cl-123-1-${"a".repeat(40)}`;
const report = "<malformed raw JUnit & diagnostic bytes";

function fixture(
  type: "file" | "symlink" = "file",
  size = report.length,
  bytes = new TextEncoder().encode(report),
) {
  const writes: { key: string; content: Uint8Array; contentType?: string }[] = [];
  let reads = 0;

  const sandbox = {
    async listFiles() {
      return {
        success: true,
        path: "/tmp/omg-ci-unit-evidence",
        count: 1,
        timestamp: "fixture",
        files: [
          {
            name: "report.xml",
            absolutePath: "/tmp/omg-ci-unit-evidence/report.xml",
            relativePath: "report.xml",
            type,
            size,
            modifiedAt: "fixture",
            mode: "0600",
            permissions: { readable: true, writable: true, executable: false },
          },
        ],
      };
    },
    async readReport() {
      reads++;

      return new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      });
    },
  };

  const bucket: Pick<R2Bucket, "put"> = {
    async put(key, body, options) {
      writes.push({
        key,
        content: new Uint8Array(await new Response(body).arrayBuffer()),
        contentType:
          options?.httpMetadata && "contentType" in options.httpMetadata
            ? options.httpMetadata.contentType
            : undefined,
      });

      return {
        key,
        version: "fixture",
        size: report.length,
        etag: "fixture",
        httpEtag: "fixture",
        uploaded: new Date(0),
        checksums: { toJSON: () => ({}) },
        storageClass: "Standard",
        writeHttpMetadata() {},
      };
    },
  };

  return { sandbox, bucket, writes, reads: () => reads };
}

test("rejected raw JUnit survives privately without parsing it as accepted evidence", async () => {
  const f = fixture();
  expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("saved");
  expect(f.writes).toEqual([
    {
      key: `reports/${id}/portable-units.xml`,
      content: new TextEncoder().encode(report),
      contentType: "application/xml",
    },
  ]);
});

test("retention preserves non-UTF8 bytes and verification identities", async () => {
  const bytes = new Uint8Array([60, 255, 0, 38, 62]);
  const f = fixture("file", bytes.length, bytes);
  const verificationId = `${id}-v-${"b".repeat(16)}`;
  expect(await retainUnitReport(verificationId, f.sandbox, f.bucket)).toBe("saved");
  expect(f.writes[0]?.content).toEqual(bytes);
  expect(f.writes[0]?.key).toBe(`reports/${verificationId}/portable-units.xml`);
});

test("missing reports and provider failures remain unavailable diagnostics", async () => {
  const f = fixture();

  const missing = {
    ...f.sandbox,
    async listFiles() {
      return { ...(await f.sandbox.listFiles()), files: [] };
    },
  };

  expect(await retainUnitReport(id, missing, f.bucket)).toBe("missing");

  const failedListing = {
    ...f.sandbox,
    async listFiles() {
      return { ...(await f.sandbox.listFiles()), success: false, files: [] };
    },
  };

  expect(await retainUnitReport(id, failedListing, f.bucket)).toBe("unavailable");

  const unreadable = {
    ...f.sandbox,
    async readReport(): Promise<Workers.ReadableStream<Uint8Array>> {
      throw new Error("provider unavailable");
    },
  };

  expect(await retainUnitReport(id, unreadable, f.bucket)).toBe("unavailable");

  const failingBucket: Pick<R2Bucket, "put"> = {
    async put() {
      throw new Error("storage unavailable");
    },
  };

  expect(await retainUnitReport(id, f.sandbox, failingBucket)).toBe("unavailable");
  expect(f.writes).toEqual([]);
});

test("actual stream bytes cannot exceed the report cap despite smaller metadata", async () => {
  const f = fixture("file", 1, new Uint8Array(20_000_001));
  expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("oversized");
  expect(f.writes).toEqual([]);
});

test("a prematurely ended RPC stream cannot be retained as a complete report", async () => {
  const f = fixture("file", report.length + 1);
  expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("unavailable");
  expect(f.writes).toEqual([]);
});

test("retention rejects untrusted identities, linked files and oversized reports before reading", async () => {
  for (const [runId, type, size, status] of [
    ["../other", "file", 1, "invalid-identity"],
    [id, "symlink", 1, "unsafe"],
    [id, "file", 20_000_001, "oversized"],
  ] as const) {
    const f = fixture(type, size);
    expect(await retainUnitReport(runId, f.sandbox, f.bucket)).toBe(status);
    expect(f.reads()).toBe(0);
    expect(f.writes).toEqual([]);
  }
});

test("candidate source admission denies hard links, root-owned files and oversized input", () => {
  const regular = { isFile: () => true, uid: 10001, nlink: 1, size: 10 };
  expect(candidateReportStatus(regular)).toBe("ready");
  expect(candidateReportStatus({ ...regular, nlink: 2 })).toBe("unsafe");
  expect(candidateReportStatus({ ...regular, uid: 0 })).toBe("unsafe");
  expect(candidateReportStatus({ ...regular, isFile: () => false })).toBe("unsafe");
  expect(candidateReportStatus({ ...regular, size: 20_000_001 })).toBe("oversized");
});


test("raw runner logs retain exact bytes only in the private diagnostic namespace", async () => {
  for (const stream of ["stdout", "stderr"]) {
    const bytes = new Uint8Array([60,255,0,38,62]);
    const f = fixture("file", bytes.length, bytes);
    const sandbox = {
      ...f.sandbox,
      async listFiles(directory: string) {
        expect(directory).toBe("/tmp");
        const listing = await f.sandbox.listFiles();
        return {...listing, files: listing.files.map(file=>({...file,absolutePath:`/tmp/ci-step.${stream === "stdout" ? "out" : "err"}`}))};
      },
    };
    const auditId = `${id}-ta-${"b".repeat(16)}`;
    expect(await retainRunnerLog(auditId,"test-audit-four-state",stream,sandbox,f.bucket)).toBe("saved");
    expect(f.writes).toEqual([{key:`diagnostics/runner-logs/${auditId}/test-audit-four-state.${stream}`,content:bytes,contentType:"text/plain; charset=utf-8"}]);
  }
});

test("raw runner log admission rejects invalid metadata and unsafe files before reading", async () => {
  for (const [runId,step,stream] of [["../outside","script-contracts","stdout"],[id,"../outside","stdout"],[id,"script-contracts","../outside"],[id,"unknown","stderr"]]) {
    const f=fixture();
    expect(await retainRunnerLog(runId,step,stream,f.sandbox,f.bucket)).toBe("invalid-identity");
    expect(f.reads()).toBe(0);
    expect(f.writes).toEqual([]);
  }
  for (const [type,size,status] of [["symlink",1,"unsafe"],["file",20_000_001,"oversized"]] as const) {
    const f=fixture(type,size);
    const sandbox={...f.sandbox,async listFiles(){const listing=await f.sandbox.listFiles();return {...listing,files:listing.files.map(file=>({...file,absolutePath:"/tmp/ci-step.err"}))};}};
    expect(await retainRunnerLog(id,"script-contracts","stderr",sandbox,f.bucket)).toBe(status);
    expect(f.reads()).toBe(0);
    expect(f.writes).toEqual([]);
  }
});
