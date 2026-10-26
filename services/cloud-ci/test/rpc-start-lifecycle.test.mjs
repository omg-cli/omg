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

const { RpcSession } =
    await import("../node_modules/capnweb/dist/index-bun.js");
function pair() {
    const mk = () => {
        const l = new Map(),
            s = {
                peer: null,
                accept() {},
                addEventListener(t, f) {
                    l.set(t, [...(l.get(t) || []), f]);
                },
                removeEventListener(t, f) {
                    l.set(
                        t,
                        (l.get(t) || []).filter((x) => x !== f),
                    );
                },
                deliver(t, e) {
                    for (const f of l.get(t) || []) f(e);
                },
                send(d) {
                    queueMicrotask(() =>
                        s.peer.deliver("message", { data: d }),
                    );
                },
                close(c = 1000, r = "") {
                    queueMicrotask(() => {
                        s.peer.deliver("close", { code: c, reason: r });
                        s.deliver("close", { code: c, reason: r });
                    });
                },
            };
        return s;
    };
    const a = mk(),
        b = mk();
    a.peer = b;
    b.peer = a;
    return [a, b];
}
function tx(s) {
    const q = [];
    let w, e;
    s.addEventListener("message", (x) => {
        if (typeof x.data !== "string") return;
        if (w) {
            const r = w;
            w = null;
            r(x.data);
        } else q.push(x.data);
    });
    s.addEventListener("close", (x) => {
        e ??= new Error(`Peer closed WebSocket: ${x.code} ${x.reason}`);
    });
    s.addEventListener("error", () => {
        e ??= new Error("WebSocket connection failed.");
    });
    return {
        send(m) {
            s.send(m);
        },
        receive() {
            if (q.length) return Promise.resolve(q.shift());
            if (e) return Promise.reject(e);
            return new Promise((r) => {
                w = r;
            });
        },
    };
}
async function open() {
    const h = {
        logger: { debug() {}, info() {}, warn() {}, error() {} },
        ctx: {
            storage: { async delete() {}, async put() {} },
            id: { toString: () => "fixture" },
        },
        currentLifetime: { async rotate() {} },
        currentRuntime: { async clear() {} },
        activeMounts: new Map(),
        async clearActivePreviewPorts() {},
        ensureTunnelsBuilt() {},
        computeRetryTimeoutMs: () => 1,
        renewActivityTimeout() {},
        isNoInstanceError: () => false,
        buildDisconnectCause: Sandbox.prototype.buildDisconnectCause,
        createSandboxClient: () => ({ disconnect() {} }),
        async startContainerForRPC() {},
    };
    const c = Sandbox.prototype.createClientForTransport.call(h, "rpc");
    h.client = c;
    const [a, b] = pair(),
        started = [];
    c.connOptions.stub = {
        async fetch() {
            return { status: 101, webSocket: a };
        },
    };
    const session = new RpcSession(tx(b), {
        commands: {
            async execute(cmd) {
                started.push(cmd);
                await new Promise(() => {});
            },
        },
    });
    c.stopBusyPoll();
    await c.connect();
    return { c, b, started, session };
}
async function wait(s, n = 1) {
    for (let i = 0; i < 200 && s.length < n; i++)
        await new Promise((r) => setTimeout(r, 5));
    expect(s.length).toBeGreaterThanOrEqual(n);
}
async function settle(p) {
    let t;
    try {
        return await Promise.race([
            p,
            new Promise((_, j) => {
                t = setTimeout(() => j(new Error("deadline")), 2000);
            }),
        ]);
    } finally {
        clearTimeout(t);
    }
}
async function close(c, b, s) {
    c.stopBusyPoll();
    c.conn?.disconnect();
    s[Symbol.dispose]?.();
    b.close(1000, "cleanup");
}
test("cause-less close preserves peer metadata on both in-flight calls", async () => {
    const { c, b, started, session } = await open();
    try {
        const x = c.commands.execute("tail -c 64 /tmp/ci-step.out"),
            y = c.commands.execute("tail -c 64 /tmp/ci-step.out");
        await wait(started, 2);
        b.close(4001, "probe-close");
        const [p, q] = await Promise.all([
            settle(
                x.then(
                    () => null,
                    (v) => v,
                ),
            ),
            settle(
                y.then(
                    () => null,
                    (v) => v,
                ),
            ),
        ]);
        expect(p.name).toBe("OperationInterruptedError");
        expect(p.code).toBe("OPERATION_INTERRUPTED");
        expect(p.context).toEqual({
            reason: "transport_disposed",
            operation: "commands.execute",
            phase: "rpc_call",
            admitted: true,
            retryable: false,
            kind: "peer_closed",
            closeCode: 4001,
        });
        expect(q.context).toEqual(p.context);
        expect(c.conn).toBeNull();
    } finally {
        await close(c, b, session);
    }
});
test("invalid close code is dropped while peer kind survives", async () => {
    const { c, b, started, session } = await open();
    try {
        const p = c.commands.execute("tail -c 64 /tmp/ci-step.out");
        await wait(started);
        b.close(6000, "probe-close");
        const e = await settle(
            p.then(
                () => null,
                (v) => v,
            ),
        );
        expect(e.context.kind).toBe("peer_closed");
        expect(e.context.reason).toBe("transport_disposed");
        expect(e.context.retryable).toBe(false);
        expect(Object.hasOwn(e.context, "closeCode")).toBe(false);
    } finally {
        await close(c, b, session);
    }
});

test("socket errors preserve structured identity on both pending calls", async () => {
  const { c, b, started, session } = await open();
  try {
    const first = c.commands.execute("tail -c 64 /tmp/ci-step.out");
    const second = c.commands.execute("tail -c 64 /tmp/ci-step.err");
    await wait(started, 2);
    b.peer.deliver("error", {});
    const failures = await Promise.all([
      settle(first.then(() => null, (error) => error)),
      settle(second.then(() => null, (error) => error)),
    ]);
    for (const failure of failures) {
      expect(failure.code).toBe("OPERATION_INTERRUPTED");
      expect(failure.context).toEqual({
        reason: "transport_disposed", operation: "commands.execute", phase: "rpc_call",
        admitted: true, retryable: false, kind: "connection_failed",
      });
    }
    expect(c.conn).toBeNull();
  } finally {
    await close(c, b, session);
  }
});