import { expect, mock, test } from "bun:test";

const evidence = new Map();
const pending = [];

await Promise.resolve(
  mock.module("@cloudflare/ci/worker", () => ({
    CiSandbox: class {
      calls = [];
      failRead = false;
      probeExitCode = 0;
      ctx = {
        storage: {
          values: new Map(),
          async put(key, value) { this.values.set(key, structuredClone(value)); },
          async get(key) { return structuredClone(this.values.get(key)); },
        },
        id: { toString: () => "a".repeat(64) },
        waitUntil(value) {
          pending.push(value);
        },
        blockConcurrencyWhile(callback) {
          this.initialization = callback();
          return this.initialization;
        },
      };
      env = {
        BACKUP_BUCKET: {
          async put(key, value) {
            evidence.set(key, value);

            return {};
          },
        },
      };
      async createBackup(options) {
        await this.ctx.initialization;
        return options;
      }
      async restoreBackup(backup) {
        await this.ctx.initialization;
        return backup;
      }
      async execWithSessionToken(command) {
        await this.ctx.initialization;
        return { exitCode: this.probeExitCode, command };
      }
      async onStop() { await this.ctx.initialization; }
      async onActivityExpired() { await this.ctx.initialization; }
      async startProcess() { await this.ctx.initialization; }
      async listFiles(directory) {
        await this.ctx.initialization;
        this.calls.push("list");
        if(directory === "/tmp") return {success:true,files:["out","err"].map(extension=>({absolutePath:"/tmp/ci-step."+extension,type:"file",size:5}))};

        return {
          success: true,
          files: [
            { absolutePath: "/tmp/omg-ci-unit-evidence/report.xml", type: "file", size: 5 },
          ],
        };
      }
      async readFile(path, options) {
        await this.ctx.initialization;
        this.calls.push("read");
        if(path === "/tmp/ci-step.out" || path === "/tmp/ci-step.err") {
          if(this.failRead) throw new Error("private provider detail");
          return {content:new ReadableStream({start(controller){controller.enqueue(new Uint8Array([60,255,0,38,62]));controller.close();}})};
        }
        expect(path).toBe("/tmp/omg-ci-unit-evidence/report.xml");
        expect(options).toEqual({ encoding: "none" });

        if (this.failRead) throw new Error("private provider detail");

        return {
          content: new ReadableStream({
            start(controller) {
              controller.enqueue(new Uint8Array([60, 255, 0, 38, 62]));
              controller.close();
            },
          }),
        };
      }
      async destroy() {
        await this.ctx.initialization;
        this.calls.push("destroy");
      }
    },
  })),
);

const { CiSandbox } = await import("../src/sandbox.ts");

test("real adapter retains only the unit stage's bounded private report before destroying", async () => {
  const id = `cl-123-1-${"a".repeat(40)}`;

  for (const failure of ["none", "read", "write"]) {
    const sandbox = new CiSandbox();
    sandbox.failRead = failure === "read";
    sandbox.env.BACKUP_BUCKET.put = async (key, body) => {
      if (!key.startsWith("reports/")) return {};
      sandbox.calls.push("put");

      if (failure === "write") throw new Error("private storage detail");
      expect(key).toBe(`reports/${id}/portable-units.xml`);
      expect(new Uint8Array(await new Response(body).arrayBuffer())).toEqual(
        new Uint8Array([60, 255, 0, 38, 62]),
      );

      return {};
    };

    await sandbox.startProcess(
      "(node /opt/omg-ci/run.mjs rust-portable-tests) > /tmp/ci-stdout.log 2> /tmp/ci-stderr.log",
      {
        env: { OMG_REPORT_RUN_ID: id, OMG_CI_LEAF_STEP: "rust-portable-tests" },
      },
    );
    await sandbox.destroy();
    expect(sandbox.calls).toEqual(
      failure === "read" ? ["list", "read", "destroy"] : ["list", "read", "put", "destroy"],
    );
  }

  for (const [stage, runId] of [
    ["source-static", id],
    ["rust-portable-tests", "../invalid"],
    [undefined, id],
  ]) {
    const sandbox = new CiSandbox();
    await sandbox.startProcess("wrapped trusted command", {
      env: { OMG_REPORT_RUN_ID: runId, OMG_CI_LEAF_STEP: stage },
    });
    await sandbox.destroy();
    expect(sandbox.calls).toEqual(["destroy"]);
  }
});

test("trusted unit stage metadata retains evidence independently of SDK command wrappers", async () => {
  for (const command of [
    "(node /opt/omg-ci/run.mjs rust-portable-tests) > /tmp/stdout 2> /tmp/stderr",
    "another SDK wrapper",
  ]) {
    const sandbox = new CiSandbox();
    await sandbox.startProcess(command, {
      env: {
        OMG_REPORT_RUN_ID: `cl-123-1-${"a".repeat(40)}`,
        OMG_CI_LEAF_STEP: "rust-portable-tests",
      },
    });
    await sandbox.destroy();
    expect(sandbox.calls).toEqual(["list", "read", "destroy"]);
  }
});

test("real adapter preserves full backup options unless a known terminal role is present", async () => {
  for (const name of [
    "source-format",
    "rust-portable-tests",
    "install",
    "unknown",
    "regression-red-green",
  ]) {
    const sandbox = new CiSandbox();
    await sandbox.startProcess("trusted command", { env: { OMG_CI_LEAF_STEP: name } });
    const options = { dir: "/workspace", excludes: ["caller-pattern"] };
    const result = await sandbox.createBackup(options);
    expect(result).toEqual({
      ...options,
      localBucket: true,
      excludes: ["source-format", "rust-portable-tests"].includes(name)
        ? ["*", ".*"]
        : options.excludes,
    });
  }
});

test("a cached backup handle restores through the R2 binding even when its local flag was lost", async () => {
  const sandbox = new CiSandbox();
  const restored = await sandbox.restoreBackup({ id: "cached-backup", dir: "/workspace" });
  expect(restored).toEqual({ id: "cached-backup", dir: "/workspace", localBucket: true });
  expect(await sandbox.createBackup({ dir: "/workspace" })).toEqual({
    dir: "/workspace",
    localBucket: true,
  });
});

test("configured private signing preserves native FUSE mode and excludes secrets from diagnostics", async () => {
  const sandbox = new CiSandbox();
  sandbox.env.R2_ACCESS_KEY_ID = "fixture-access";
  sandbox.env.R2_SECRET_ACCESS_KEY = "fixture-secret";
  expect(await sandbox.restoreBackup({ id: "unprobed", dir: "/workspace" })).toEqual({
    id: "unprobed",
    dir: "/workspace",
    localBucket: true,
  });
  await sandbox.execWithSessionToken("test -c /dev/fuse", "fixture-session");
  expect(await sandbox.createBackup({ dir: "/workspace", localBucket: false })).toEqual({
    dir: "/workspace",
    localBucket: false,
  });
  expect(await sandbox.restoreBackup({ id: "cached-native", dir: "/workspace" })).toEqual({
    id: "cached-native",
    dir: "/workspace",
    localBucket: false,
  });
  await Promise.all(pending);
  const body = evidence.get(`diagnostics/sandboxes/${"a".repeat(64)}.json`);
  expect(body).toContain('"fuseExitCode":0');
  expect(body).not.toContain("fixture-access");
  expect(body).not.toContain("fixture-secret");
});

test("missing signing credentials and unavailable FUSE keep native binding fallback", async () => {
  for (const credentials of [
    {},
    { R2_ACCESS_KEY_ID: "fixture-access" },
    { R2_SECRET_ACCESS_KEY: "fixture-secret" },
    { R2_ACCESS_KEY_ID: "fixture-access", R2_SECRET_ACCESS_KEY: "fixture-secret" },
  ]) {
    const sandbox = new CiSandbox();
    Object.assign(sandbox.env, credentials);
    sandbox.probeExitCode = 1;
    await sandbox.execWithSessionToken("test -c /dev/fuse", "fixture-session");
    expect(await sandbox.createBackup({ dir: "/workspace", localBucket: true })).toEqual({
      dir: "/workspace",
      localBucket: true,
    });
    expect(await sandbox.restoreBackup({ id: "cached-binding", dir: "/workspace" })).toEqual({
      id: "cached-binding",
      dir: "/workspace",
      localBucket: true,
    });
  }
});

test("native session-disabled execution records phases without retaining commands or session tokens", async () => {
  const sandbox = new CiSandbox();
  const result = await sandbox.execWithSessionToken("test -c /dev/fuse", "private-session-token");
  await Promise.all(pending);
  expect(result.exitCode).toBe(0);
  const body = evidence.get(`diagnostics/sandboxes/${"a".repeat(64)}.json`);
  expect(body).toContain('"phase":"preflight"');
  expect(body).not.toContain("private-session-token");
  expect(body).not.toContain("test -c");
});

test("lifecycle diagnostics retain bounded stop reason and exit code before SDK cleanup", async () => {
  const sandbox = new CiSandbox();
  await sandbox.onStop({ reason: "exit", exitCode: 137 });
  await sandbox.onActivityExpired();
  await Promise.all(pending);
  const body = evidence.get(`diagnostics/sandboxes/${"a".repeat(64)}.json`);
  expect(body).toContain('"stop":{"reason":"exit","exitCode":137}');
  expect(body).toContain('"phase":"activity-expired"');
});


test("real adapter retains raw runner diagnostics before destroy without accepting them as proof", async () => {
  const id=`cl-123-1-${"a".repeat(40)}-ta-${"b".repeat(16)}`;
  for(const failure of ["none","read","write"]){
    const sandbox=new CiSandbox();
    sandbox.failRead=failure === "read";
    const stored=new Map();
    sandbox.env.BACKUP_BUCKET.put=async(key,body)=>{
      if(!key.startsWith("diagnostics/runner-logs/"))return {};
      if(failure === "write")throw new Error("private storage detail");
      sandbox.calls.push("put");
      stored.set(key,new Uint8Array(await new Response(body).arrayBuffer()));
      return {};
    };
    await sandbox.startProcess("trusted wrapped command",{env:{OMG_DIAGNOSTIC_RUN_ID:id,OMG_CI_LEAF_STEP:"script-contracts"}});
    await sandbox.destroy();
    expect(sandbox.calls.at(-1)).toBe("destroy");
    expect([...stored.keys()].sort()).toEqual(failure === "none"?[`diagnostics/runner-logs/${id}/script-contracts.stderr`,`diagnostics/runner-logs/${id}/script-contracts.stdout`]:[]);
    for(const value of stored.values())expect(value).toEqual(new Uint8Array([60,255,0,38,62]));
  }
});


test.each(["frozen-dependencies", "script-contracts"])("recreated adapter preserves %s logs and snapshot policy", async (stage) => {
  const id = `cl-456-1-${"c".repeat(40)}`;
    const first = new CiSandbox();
    await first.startProcess("trusted wrapped command", { env: {
      OMG_DIAGNOSTIC_RUN_ID: id, OMG_CI_LEAF_STEP: stage,
    } });
    const restarted = new CiSandbox();
    restarted.ctx.storage = first.ctx.storage;
    const stored = new Map();
    restarted.env.BACKUP_BUCKET.put = async (key, body) => {
      if (key.startsWith("diagnostics/runner-logs/"))
        stored.set(key, new Uint8Array(await new Response(body).arrayBuffer()));
      return {};
    };
    const backup = await restarted.createBackup({ path: "/workspace" });
    expect(backup.excludes).toEqual(stage === "frozen-dependencies" ? undefined : ["*", ".*"]);
    await restarted.destroy();
    expect([...stored.keys()].sort()).toEqual([
      `diagnostics/runner-logs/${id}/${stage}.stderr`,
      `diagnostics/runner-logs/${id}/${stage}.stdout`,
    ]);
    for (const bytes of stored.values()) expect(bytes).toEqual(new Uint8Array([60,255,0,38,62]));
    expect(restarted.calls.at(-1)).toBe("destroy");
});

test.each(["missing-metadata", "saved", "unavailable"])("teardown records %s diagnostic custody without accepting test proof", async (mode) => {
  const sandbox = new CiSandbox();
  sandbox.failRead = mode === "unavailable";
  if (mode !== "missing-metadata") {
    await sandbox.startProcess("private command", { env: {
      OMG_DIAGNOSTIC_RUN_ID: `cl-789-1-${"d".repeat(40)}`,
      OMG_CI_LEAF_STEP: "source-format", PRIVATE_VALUE: "private-credential",
    } });
  }
  await sandbox.destroy();
  const body = evidence.get(`diagnostics/sandboxes/${"a".repeat(64)}-retention.json`);
  expect(body).toBeDefined();
  expect(JSON.parse(body)).toEqual({
    metadataPresent: mode !== "missing-metadata",
    runIdentityPresent: mode !== "missing-metadata",
    leafIdentityPresent: mode !== "missing-metadata",
    streams: mode === "missing-metadata" ? [] : [
      { stream: "stdout", status: mode }, { stream: "stderr", status: mode },
    ],
  });
  expect(body).not.toContain("private command");
  expect(body).not.toContain("private-credential");
  expect(sandbox.calls.at(-1)).toBe("destroy");
});

test("an unavailable retention diagnostic cannot prevent sandbox destruction", async () => {
  const sandbox = new CiSandbox();
  sandbox.env.BACKUP_BUCKET.put = async (key) => {
    if (key.endsWith("-retention.json")) throw new Error("private provider detail");
    return {};
  };
  await sandbox.destroy();
  expect(sandbox.calls.at(-1)).toBe("destroy");
});
