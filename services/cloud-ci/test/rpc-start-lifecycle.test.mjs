import { expect, mock, test } from "bun:test";

await Promise.resolve(
  mock.module("cloudflare:workers", () => ({
    DurableObject: class {},
    RpcTarget: class {},
    WorkerEntrypoint: class {},
    tracing: undefined,
  })),
);

const { Sandbox } = await import("@cloudflare/sandbox");

function deferred() {
  let resolve, reject;

  const promise = new Promise((accept, fail) => {
    resolve = accept;
    reject = fail;
  });

  return { promise, resolve, reject };
}

function destroyFixture(transport = "rpc") {
  const events = [];
  const gate = deferred();
  const entered = deferred();

  const host = {
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    ctx: { storage: { async delete() {}, async put() {} }, id: { toString: () => "fixture" } },
    currentLifetime: { async rotate() {} },
    currentRuntime: { async clear() {} },
    activeMounts: new Map(),
    async clearActivePreviewPorts() {},
    ensureTunnelsBuilt() {},
    computeRetryTimeoutMs: () => 1,
    renewActivityTimeout() {},
    isNoInstanceError: () => false,
    buildDisconnectCause: Sandbox.prototype.buildDisconnectCause,
    createSandboxClient: () => ({
      disconnect() {
        events.push("disconnect-http");
      },
    }),
    alive: false,
  };

  const client = Sandbox.prototype.createClientForTransport.call(host, transport);
  host.client = client;
  let connection;

  if (transport === "rpc") {
    connection = client.getConnection();
    client.stopBusyPoll();
    connection.connectPromise = gate.promise.then(
      () => {
        events.push("started");
        host.alive = true;
      },
      (error) => {
        client.connOptions.onConnectionError(error);
        throw error;
      },
    );
  }

  const disconnect = client.disconnect;
  client.disconnect = function (cause) {
    entered.resolve();

    return disconnect.call(this, cause);
  };

  const parent = Object.getPrototypeOf(Sandbox.prototype);
  const originalDestroy = parent.destroy;
  parent.destroy = async function () {
    events.push("kill");
    this.alive = false;
  };

  return {
    host,
    client,
    connection,
    gate,
    entered,
    events,
    restore() {
      parent.destroy = originalDestroy;
    },
  };
}

test("destroy waits for actual pending RPC settlement before its final kill", async () => {
  const state = destroyFixture();
  let finished = false;

  const destroyed = Sandbox.prototype.doDestroy.call(state.host).then(() => {
    finished = true;
  });

  try {
    await state.entered.promise;
    expect(finished).toBe(false);
    expect(state.events).toEqual([]);
  } finally {
    state.gate.resolve();
    await destroyed;
    state.restore();
  }

  expect(state.events).toEqual(["started", "kill"]);
  expect(state.host.alive).toBe(false);
  expect(state.client.conn).toBeNull();
});

test("startup rejection preserves its authoritative cause while destroy still finishes", async () => {
  const state = destroyFixture();
  const cause = new Error("actual allocation refused");
  const destroyed = Sandbox.prototype.doDestroy.call(state.host);

  try {
    await state.entered.promise;
    state.gate.reject(cause);
    await destroyed;
    expect(state.client.lastConnectionError).toBe(cause);
    expect(state.client.connectionErrorIsAuthoritative).toBe(true);
    expect(state.events).toEqual(["kill"]);
    expect(state.host.alive).toBe(false);
  } finally {
    state.restore();
  }
});

test("disconnect settlement failure still kills and preserves the original error", async () => {
  const state = destroyFixture();
  const cause = new Error("injected settlement failure");
  state.gate.resolve();
  await state.connection.connectPromise;
  state.connection.whenSettled = async () => {
    throw cause;
  };

  try {
    await expect(Sandbox.prototype.doDestroy.call(state.host)).rejects.toBe(cause);
    expect(state.events).toEqual(["started", "kill"]);
    expect(state.host.alive).toBe(false);
    expect(state.client.conn).toBeNull();
  } finally {
    state.gate.resolve();
    state.restore();
  }
});

test("established RPC and HTTP destruction still reach the final kill", async () => {
  for (const transport of ["rpc", "http"]) {
    const state = destroyFixture(transport);

    if (state.connection) state.connection.connectPromise = null;

    try {
      await Sandbox.prototype.doDestroy.call(state.host);
      expect(state.events).toEqual(transport === "http" ? ["disconnect-http", "kill"] : ["kill"]);
      expect(state.host.alive).toBe(false);
    } finally {
      state.restore();
    }
  }
});

test("deferred disconnect never tears down a replacement connection", async () => {
  const state = destroyFixture();
  let replacementDisconnected = false;

  const replacement = {
    disconnect() {
      replacementDisconnected = true;
    },
  };

  try {
    const pending = state.client.disconnect(new Error("old connection ended"));
    state.client.conn = replacement;
    state.gate.resolve();
    await pending;
    expect(state.client.conn).toBe(replacement);
    expect(replacementDisconnected).toBe(false);
  } finally {
    state.connection.disconnect();
    state.restore();
  }
});

test("transport switching awaits the previous client's pending startup", async () => {
  const state = destroyFixture();
  let finished = false;
  state.host.createClientForTransport = () => ({ interpreter: {} });
  state.host.transport = "rpc";

  const switched = Sandbox.prototype.setTransport.call(state.host, "http").then(() => {
    finished = true;
  });

  try {
    await state.entered.promise;
    expect(finished).toBe(false);
  } finally {
    state.gate.resolve();
    await switched;
    state.restore();
  }

  expect(state.client.conn).toBeNull();
  expect(state.host.client).not.toBe(state.client);
});

function fixture(transport, initiallyConnected, connectDuringCleanup = false) {
  const cleanup = [];
  let connected = initiallyConnected;
  let disconnected = false;

  const storage = {
    async get() {},
    async put() {},
    async transaction(operation) {
      cleanup.push("tunnels");
      await operation(storage);
    },
    async delete(key) {
      cleanup.push(key);
    },
  };

  const host = {
    transport,
    containerGeneration: 0,
    defaultSession: "old-session",
    defaultSessionInit: Promise.resolve(),
    logger: {
      debug() {},
      error(error) {
        throw error;
      },
    },
    currentRuntime: {
      async clear() {
        cleanup.push("runtime");

        if (connectDuringCleanup) connected = true;
      },
    },
    async clearActivePreviewPorts() {
      cleanup.push("preview");
    },
    async releaseRestoredMountRoutes() {
      cleanup.push("routes");
    },
    buildDisconnectCause: Sandbox.prototype.buildDisconnectCause,
    ctx: { storage },
    client: {
      isWebSocketConnected: () => connected,
      disconnect() {
        disconnected = true;
      },
    },
    activeMounts: new Map([
      [
        "local-fixture",
        {
          mountType: "local-sync",
          syncManager: {
            async stop() {
              cleanup.push("sync");
            },
          },
        },
      ],
    ]),
  };

  return { host, cleanup, disconnected: () => disconnected };
}

test("refused-start stop preserves the pending RPC attempt and every cleanup step", async () => {
  const state = fixture("rpc", false);
  await Sandbox.prototype.onStop.call(state.host);
  expect(state.disconnected()).toBe(false);
  expect(state.cleanup).toEqual([
    "runtime",
    "preview",
    "tunnels",
    "routes",
    "sync",
    "defaultSession",
  ]);
  expect(state.host.containerGeneration).toBe(1);
  expect(state.host.defaultSession).toBeNull();
  expect(state.host.defaultSessionInit).toBeNull();
  expect(state.host.activeMounts.size).toBe(0);
});

test("stop decides before awaiting cleanup even if the pending attempt then connects", async () => {
  const state = fixture("rpc", false, true);
  await Sandbox.prototype.onStop.call(state.host);
  expect(state.disconnected()).toBe(false);
  expect(state.host.client.isWebSocketConnected()).toBe(true);
});

test("established RPC and HTTP clients still disconnect on stop", async () => {
  for (const [transport, connected] of [
    ["rpc", true],
    ["http", false],
  ]) {
    const state = fixture(transport, connected);
    await Sandbox.prototype.onStop.call(state.host);
    expect(state.disconnected()).toBe(true);
    expect(state.cleanup).toContain("defaultSession");
  }
});

test("stop disconnects the client captured before asynchronous cleanup", async () => {
  const state = fixture("rpc", true);
  let replacementDisconnected = false;
  state.host.currentRuntime.clear = async () => {
    state.host.client = {
      disconnect() {
        replacementDisconnected = true;
      },
    };
  };

  await Sandbox.prototype.onStop.call(state.host);
  expect(state.disconnected()).toBe(true);
  expect(replacementDisconnected).toBe(false);
});

function executionFixture({ pause = false } = {}) {
  const sentinel = "Runner teardown refuses container start";
  const submissions = [];
  const gate = deferred();
  const entered = deferred();
  let fenced = false;
  let guardCalls = 0;

  const host = Object.assign(Object.create(Sandbox.prototype), {
    logger: { debug() {}, info() {}, warn() {}, error() {} },
    client: {
      commands: {
        async execute(command) {
          submissions.push(`execute:${command}`);
          return { exitCode: 0, success: true, stdout: "", stderr: "" };
        },
      },
      processes: {
        async startProcess(command) {
          submissions.push(`startProcess:${command}`);
          return { processId: "fixture-process", pid: 1, command };
        },
      },
    },
    serializeExecutionContext: (context) => context.sessionId,
    validateExplicitSessionId() {},
    buildExecutionRequestOptions: () => ({}),
    getProcessSessionBinding: (session) => session,
    getPublicExecutionSessionId: (sessionId) => sessionId,
    mapExecuteResponseToExecResult: (response) => response,
    createProcessFromDTO: (data) => data,
    async executeWithStreaming(command) {
      submissions.push(`executeWithStreaming:${command}`);
      return { exitCode: 0, success: true, stdout: "", stderr: "" };
    },
    async resolveExecution() {
      if (pause) {
        entered.resolve();
        await gate.promise;
      }

      return { sessionId: "default" };
    },
    assertExecutionAllowed() {
      guardCalls += 1;
      if (fenced) throw new Error(sentinel);
    },
  });

  return {
    host,
    submissions,
    sentinel,
    gate,
    entered,
    fence() {
      fenced = true;
    },
    guardCalls: () => guardCalls,
  };
}

test("actual SDK exec paths reject at the installed guard before command submission", async () => {
  const invocations = [
    (host) => Sandbox.prototype.exec.call(host, "echo normal"),
    (host) => Sandbox.prototype.execWithSessionToken.call(host, "echo explicit", "session-1"),
    (host) => Sandbox.prototype.exec.call(host, "echo stream", { stream: true, onOutput() {} }),
  ];

  for (const invoke of invocations) {
    const state = executionFixture();
    state.fence();

    await expect(invoke(state.host)).rejects.toThrow(state.sentinel);
    expect(state.submissions).toEqual([]);
    expect(state.guardCalls()).toBe(1);
  }
});

test("actual SDK startProcess released after fencing rejects before process submission", async () => {
  const state = executionFixture({ pause: true });
  const pending = Sandbox.prototype.startProcess.call(state.host, "sleep 2", { env: {} });

  await state.entered.promise;
  state.fence();
  state.gate.resolve();

  await expect(pending).rejects.toThrow(state.sentinel);
  expect(state.submissions).toEqual([]);
  expect(state.guardCalls()).toBe(1);
});
