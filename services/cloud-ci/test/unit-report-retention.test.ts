import { expect, test } from "bun:test";
import type * as Workers from "@cloudflare/workers-types/index.ts";
import {
  releaseTerminalOwner,
  retainRunnerLog,
  retainSandboxEvidence,
  retainUnitReport,
} from "../src/unit-report-retention";
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
    async listFiles(path = "/tmp/omg-ci-unit-evidence") {
      if (path === "/tmp") {
        return {
          success: true,
          path: "/tmp",
          count: 1,
          timestamp: "fixture",
          files: [
            {
              name: "omg-ci-unit-evidence",
              absolutePath: "/tmp/omg-ci-unit-evidence",
              relativePath: "omg-ci-unit-evidence",
              type: "directory" as const,
              size: 0,
              modifiedAt: "fixture",
              mode: "0700",
              permissions: { readable: true, writable: true, executable: true },
            },
          ],
        };
      }

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
      return { ...(await f.sandbox.listFiles()), count: 0, files: [] };
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

function logFixture(type: "file" | "symlink", size = report.length) {
  const f = fixture(type, size);

  return {
    ...f,
    sandbox: {
      ...f.sandbox,
      async listFiles(directory: string) {
        expect(directory).toBe("/tmp");
        const listing = await f.sandbox.listFiles();
        const base = listing.files[0]!;

        return {
          ...listing,
          files: ["out", "err"].map((stream) => ({
            ...base,
            name: `ci-step.${stream}`,
            absolutePath: `/tmp/ci-step.${stream}`,
            relativePath: `ci-step.${stream}`,
          })),
        };
      },
    },
  };
}

test("terminal release keeps the container when actual runner-log retention is unsafe", async () => {
  const f = logFixture("symlink");
  const owner = `${id}-ta-${"b".repeat(16)}`;
  let destroyed = 0;

  await expect(
    releaseTerminalOwner({
      readOwner: async () => owner,
      lookup: async (instanceId) => ({ id: instanceId, status: "complete" }),
      retain: () =>
        retainSandboxEvidence(
          { diagnosticRunId: owner, leafStep: "test-audit-four-state" },
          f.sandbox,
          () => f.sandbox.readReport(),
          f.bucket,
        ),
      destroy: async () => {
        destroyed++;
      },
      delegate: async () => {},
      warn: () => {},
    }),
  ).rejects.toThrow("runner-log:stdout:unsafe");

  expect(destroyed).toBe(0);
  expect(f.writes).toEqual([]);
});

test("terminal release keeps the container when an existing report is unsafe", async () => {
  const f = fixture("symlink", 1);
  const owner = `${id}-v-${"b".repeat(16)}`;
  let destroyed = 0;

  await expect(
    releaseTerminalOwner({
      readOwner: async () => owner,
      lookup: async (instanceId) => ({ id: instanceId, status: "errored" }),
      retain: () =>
        retainSandboxEvidence({ reportRunId: owner }, f.sandbox, () => f.sandbox.readReport(), f.bucket),
      destroy: async () => {
        destroyed++;
      },
      delegate: async () => {},
      warn: () => {},
    }),
  ).rejects.toThrow("unit-report:unsafe");

  expect(destroyed).toBe(0);
});

test("terminal release never deletes an owner reassigned while the workflow lookup is pending", async () => {
  const f = fixture();
  const owner = `${id}-v-${"b".repeat(16)}`;
  const replacement = `${id}-v-${"c".repeat(16)}`;
  let ownerReads = 0;
  let destroyed = 0;
  let delegated = 0;

  const result = await releaseTerminalOwner({
    readOwner: async () => (++ownerReads === 1 ? owner : replacement),
    lookup: async (instanceId) => {
      await Promise.resolve();

      return { id: instanceId, status: "complete" };
    },
    retain: () =>
      retainSandboxEvidence({ reportRunId: owner }, f.sandbox, () => f.sandbox.readReport(), f.bucket),
    destroy: async () => {
      destroyed++;
    },
    delegate: async () => {
      delegated++;
    },
    warn: () => {},
  });

  expect(result).toBe("retained-owner-changed");
  expect(destroyed).toBe(0);
  expect(delegated).toBe(1);
});

test("terminal release preserves a live owner without retaining or deleting", async () => {
  const f = fixture();
  const owner = `${id}-v-${"b".repeat(16)}`;
  let destroyed = 0;
  let delegated = 0;

  const result = await releaseTerminalOwner({
    readOwner: async () => owner,
    lookup: async (instanceId) => ({ id: instanceId, status: "running" }),
    retain: () =>
      retainSandboxEvidence({ reportRunId: owner }, f.sandbox, () => f.sandbox.readReport(), f.bucket),
    destroy: async () => {
      destroyed++;
    },
    delegate: async () => {
      delegated++;
    },
    warn: () => {},
  });

  expect(result).toBe("retained-active");
  expect(destroyed).toBe(0);
  expect(delegated).toBe(1);
  expect(f.writes).toEqual([]);
});

test("terminal release destroys only after actual retention saves the report", async () => {
  const f = fixture();
  const owner = `${id}-v-${"b".repeat(16)}`;
  let destroyed = 0;

  const result = await releaseTerminalOwner({
    readOwner: async () => owner,
    lookup: async (instanceId) => ({ id: instanceId, status: "complete" }),
    retain: () =>
      retainSandboxEvidence({ reportRunId: owner }, f.sandbox, () => f.sandbox.readReport(), f.bucket),
    destroy: async () => {
      destroyed++;
    },
    delegate: async () => {
      throw new Error("delegate must not run");
    },
    warn: () => {},
  });

  expect(result).toBe("released");
  expect(destroyed).toBe(1);
  expect(f.writes.map((write) => write.key)).toEqual([`reports/${owner}/portable-units.xml`]);
});


type ParentEntry = { name: string; absolutePath: string; type: "file" | "directory" | "symlink" };

function parentFixture(
  parent: ParentEntry[] | "failed" | "throw" | "partial",
  child: "success" | "empty" | "failed" | "throw" = "success",
) {
  const f = fixture();
  let childListings = 0;
  const directory: ParentEntry = { name: "omg-ci-unit-evidence", absolutePath: "/tmp/omg-ci-unit-evidence", type: "directory" };
  const sandbox = {
    ...f.sandbox,
    async listFiles(path: string) {
      if (path === "/tmp") {
        if (parent === "throw") throw new Error("permission denied");
        if (parent === "failed") return { success: false, path: "/tmp", count: 0, timestamp: "fixture", files: [] };
        const files = parent === "partial" ? [directory] : parent;
        return {
          success: true,
          path: "/tmp",
          count: parent === "partial" ? 2 : files.length,
          timestamp: "fixture",
          files: files.map((entry) => ({
            ...entry,
            relativePath: entry.name,
            size: 0,
            modifiedAt: "fixture",
            mode: "0700",
            permissions: { readable: true, writable: true, executable: true },
          })),
        };
      }
      childListings++;
      if (child === "throw") throw new Error("transport failed");
      if (child === "failed") return { ...(await f.sandbox.listFiles(path)), success: false, count: 0, files: [] };
      if (child === "empty") return { ...(await f.sandbox.listFiles(path)), count: 0, files: [] };
      return f.sandbox.listFiles(path);
    },
  };
  return { ...f, sandbox, childListings: () => childListings };
}

test("optional unit-report absence is missing only after a complete parent listing", async () => {
  const f = parentFixture([]);
  expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("missing");
  expect(f.childListings()).toBe(0);
  expect(f.reads()).toBe(0);
  expect(f.writes).toEqual([]);
});

test("empty child, wrong exact path, file parent and symlink parent are missing or unsafe", async () => {
  const empty = parentFixture([{ name: "omg-ci-unit-evidence", absolutePath: "/tmp/omg-ci-unit-evidence", type: "directory" }], "empty");
  expect(await retainUnitReport(id, empty.sandbox, empty.bucket)).toBe("missing");
  expect(empty.childListings()).toBe(1);
  const wrong = parentFixture([{ name: "other", absolutePath: "/tmp/omg-ci-unit-evidence-other", type: "directory" }]);
  expect(await retainUnitReport(id, wrong.sandbox, wrong.bucket)).toBe("missing");
  expect(wrong.childListings()).toBe(0);
  for (const type of ["file", "symlink"] as const) {
    const f = parentFixture([{ name: "omg-ci-unit-evidence", absolutePath: "/tmp/omg-ci-unit-evidence", type }]);
    expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("unsafe");
    expect(f.childListings()).toBe(0);
    expect(f.reads()).toBe(0);
    expect(f.writes).toEqual([]);
  }
});

test("failed, throwing or partial parent and failed child listings remain unavailable", async () => {
  for (const parent of ["failed", "throw", "partial"] as const) {
    const f = parentFixture(parent);
    expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("unavailable");
    expect(f.childListings()).toBe(0);
  }
  for (const child of ["failed", "throw"] as const) {
    const f = parentFixture([{ name: "omg-ci-unit-evidence", absolutePath: "/tmp/omg-ci-unit-evidence", type: "directory" }], child);
    expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("unavailable");
    expect(f.childListings()).toBe(1);
  }
});

test("exact report bytes save only after parent directory type validation", async () => {
  const f = parentFixture([{ name: "omg-ci-unit-evidence", absolutePath: "/tmp/omg-ci-unit-evidence", type: "directory" }]);
  expect(await retainUnitReport(id, f.sandbox, f.bucket)).toBe("saved");
  expect(f.childListings()).toBe(1);
  expect(f.writes).toEqual([{ key: `reports/${id}/portable-units.xml`, content: new TextEncoder().encode(report), contentType: "application/xml" }]);
});

test("terminal owner releases on proven absence, blocks on linked parent and delegates while active", async () => {
  const owner = `${id}-v-${"b".repeat(16)}`;
  const absent = parentFixture([]);
  let destroyed = 0;
  expect(await releaseTerminalOwner({ readOwner: async () => owner, lookup: async (instanceId) => ({ id: instanceId, status: "complete" }), retain: () => retainSandboxEvidence({ reportRunId: owner }, absent.sandbox, () => absent.sandbox.readReport(), absent.bucket), destroy: async () => { destroyed++; }, delegate: async () => { throw new Error("delegate must not run"); }, warn: () => {} })).toBe("released");
  expect(destroyed).toBe(1);
  expect(absent.childListings()).toBe(0);
  const linked = parentFixture([{ name: "omg-ci-unit-evidence", absolutePath: "/tmp/omg-ci-unit-evidence", type: "symlink" }]);
  let linkedDestroyed = 0;
  await expect(releaseTerminalOwner({ readOwner: async () => owner, lookup: async (instanceId) => ({ id: instanceId, status: "complete" }), retain: () => retainSandboxEvidence({ reportRunId: owner }, linked.sandbox, () => linked.sandbox.readReport(), linked.bucket), destroy: async () => { linkedDestroyed++; }, delegate: async () => {}, warn: () => {} })).rejects.toThrow("unit-report:unsafe");
  expect(linkedDestroyed).toBe(0);
  expect(linked.childListings()).toBe(0);
  const active = parentFixture([]);
  let activeDestroyed = 0;
  let delegated = 0;
  expect(await releaseTerminalOwner({ readOwner: async () => owner, lookup: async (instanceId) => ({ id: instanceId, status: "running" }), retain: () => retainSandboxEvidence({ reportRunId: owner }, active.sandbox, () => active.sandbox.readReport(), active.bucket), destroy: async () => { activeDestroyed++; }, delegate: async () => { delegated++; }, warn: () => {} })).toBe("retained-active");
  expect(activeDestroyed).toBe(0);
  expect(delegated).toBe(1);
  expect(active.childListings()).toBe(0);
});
