import { expect, test } from "bun:test";
import { withStepNotification } from "../node_modules/@cloudflare/ci/src/ci/step-notification.ts";
import { MAX_RUNNER_CAUSE, RUNNER_CAUSE_OMITTED, boundedCause, captureRunnerFailure, runnerFailureOf } from "../node_modules/@cloudflare/ci/src/ci/runner-failure-evidence.ts";

const identity = { runnerId: "script-contracts-00000000-0000-4000-8000-000000000000", actor: "ab".repeat(32), label: "script-contracts", diagnosticRunId: "cl-40220918875-1-7c321c2a19a9e50f85a2610eb5140cae001e7443", leaf: "script-contracts" };

function interruptionError(message, cause, context = { reason: 'runtime_replaced', operation: 'sandbox.exec', phase: 'execute', admitted: false, retryable: false }) {
  const error = new Error(message, cause ? { cause } : undefined);
  Object.defineProperty(error, 'errorResponse', { value: { code: 'OPERATION_INTERRUPTED', context } });
  return error;
}

async function reportFor(error, sensitiveValues) {
  const reports = [];
  const handle = { async fail(value) { reports.push(value); }, async succeed() { throw new Error("failure fixture cannot succeed"); } };
  let thrown;
  try {
    await withStepNotification({ handle, label: "script-contracts", command: "fixture-main", sensitiveValues }, async () => { captureRunnerFailure(error, identity); throw error; }, async (execution) => execution);
  } catch (caught) { thrown = caught; }
  return { reports, thrown };
}

test("capture keeps a frozen error and records its cause", () => {
  const cause = new Error("Durable Object reset because its code was updated.");
  const error = Object.freeze(new Error("synthetic wrapper", { cause }));
  expect(captureRunnerFailure(error, identity)).toBe(error);
  expect(error.message).toBe("synthetic wrapper");
  const evidence = runnerFailureOf(error);
  expect(evidence.cause).toBe("Durable Object reset because its code was updated.");
  expect(evidence.interruption).toBe(false);
});

test("capture never invokes an accessor", () => {
  const error = new Error("wrapper");
  Object.defineProperty(error, "cause", { get() { throw new Error("getter invoked"); } });
  expect(() => { captureRunnerFailure(error, identity); }).not.toThrow();
  expect(runnerFailureOf(error).cause).toBe("");
});

test("capture is depth bounded and cycle safe", () => {
  const a = new Error("a");
  const b = new Error("b");
  Object.defineProperty(a, "cause", { value: b });
  Object.defineProperty(b, "cause", { value: a });
  const error = new Error("wrapper", { cause: a });
  expect(() => { captureRunnerFailure(error, identity); }).not.toThrow();
  const evidence = runnerFailureOf(error);
  expect(evidence.cause).toContain("a");
  expect(evidence.cause).toContain("b");
});

test("capture returns primitives and never rewrites existing evidence", () => {
  expect(captureRunnerFailure("literal", identity)).toBe("literal");
  const error = new Error("wrapper", { cause: new Error("first") });
  captureRunnerFailure(error, identity);
  captureRunnerFailure(error, { ...identity, label: "second" });
  expect(runnerFailureOf(error).identity.label).toBe("script-contracts");
});

test("a malformed error never replaces the original", () => {
  const error = new Proxy(new Error("wrapper"), { getOwnPropertyDescriptor() { throw new Error("capture fault"); } });
  expect(captureRunnerFailure(error, identity)).toBe(error);
  expect(runnerFailureOf(error).cause).toBe("");
});

test("boundedCause redacts the complete cause before it truncates", () => {
  const first = "A".repeat(100);
  const second = "B".repeat(100);
  const cause = `${first.repeat(81)}${"x".repeat(80)}${second}`;
  const redact = (value) => value.split(first).join("[REDACTED]").split(second).join("[REDACTED]");
  const redacted = boundedCause(cause, redact);
  expect(redacted).not.toContain("AAAA");
  expect(redacted).not.toContain("BBBB");
  expect(redacted.length).toBeLessThanOrEqual(MAX_RUNNER_CAUSE);
});

test("complete capture sanitizes a long crossing secret into the fail report", async () => {
  const first = "A".repeat(100);
  const second = "B".repeat(100);
  const cause = new Error(`${first.repeat(81)}${"x".repeat(80)}${second}`);
  const error = interruptionError("outer failure", cause);
  expect(captureRunnerFailure(error, identity)).toBe(error);
  expect(runnerFailureOf(error).cause.length).toBe(cause.message.length);
  const { reports, thrown } = await reportFor(error, [first, second]);
  expect(reports.length).toBe(1);
  const reported = reports[0].error;
  expect(reported).toContain("outer failure");
  expect(reported).toContain("x".repeat(80));
  expect(reported).not.toContain("AAAA");
  expect(reported).not.toContain("BBBB");
  expect(thrown.message).toBe(reported);
});

test("an oversized cause is discarded whole, never truncated before redaction", async () => {
  const secret = "fixture-only-secret";
  const cause = new Error(`${"a".repeat(70_000)}${secret}`);
  const error = interruptionError("outer failure", cause);
  captureRunnerFailure(error, identity);
  expect(runnerFailureOf(error).cause).toBe(RUNNER_CAUSE_OMITTED);
  const { reports } = await reportFor(error, [secret]);
  expect(reports[0].error).not.toContain(secret);
  expect(reports[0].error).not.toContain("a".repeat(64));
});

test("ordinary SDK errors with a cause stay unchanged", async () => {
  const error = new Error("ordinary literal failure", { cause: new Error("transport detail") });
  const { reports, thrown } = await reportFor(error, []);
  expect(reports[0].error).toBe("ordinary literal failure");
  expect(thrown.message).toBe("ordinary literal failure");
});

test("the fail report carries the validated owner and leaf identity", async () => {
  const error = interruptionError("outer failure", new Error("reset detail"));
  const { reports } = await reportFor(error, []);
  const reported = reports[0].error;
  expect(reported).toContain("run=40220918875");
  expect(reported).toContain("attempt=1");
  expect(reported).toContain("source=7c321c2a19a9e50f85a2610eb5140cae001e7443");
  expect(reported).toContain("leaf=script-contracts");
  expect(reported).toContain(`runnerId=${identity.runnerId}`);
  expect(reported).toContain(`actor=${identity.actor}`);
  expect(reported).toContain("phase=execute");
});


test('a capture fault preserves the original error and its identity', () => {
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  const original = new Error('original');
  Object.defineProperty(original, 'errorResponse', { value: proxy });
  expect(captureRunnerFailure(original, identity)).toBe(original);
  const evidence = runnerFailureOf(original);
  expect(evidence.identity.runnerId).toBe(identity.runnerId);
  expect(evidence.identity.actor).toBe(identity.actor);
  expect(evidence.cause).toBe('original');
  expect(evidence.interruption).toBe(false);
});


test('context without the SDK interruption marker is not an interruption', async () => {
  const error = new Error('ordinary failure');
  Object.defineProperty(error, 'context', { value: { reason: 'runtime_replaced', operation: 'sandbox.exec', phase: 'execute', admitted: false, retryable: false } });
  captureRunnerFailure(error, identity);
  expect(runnerFailureOf(error).interruption).toBe(false);
  const { reports, thrown } = await reportFor(error, []);
  expect(reports[0].error).toBe('ordinary failure');
  expect(thrown.message).toBe('ordinary failure');
});


test('the fail report carries every closed SDK interruption field', async () => {
  const error = interruptionError('outer failure', new Error('reset detail'), {
    reason: 'runtime_replaced',
    operation: 'sandbox.exec',
    phase: 'durable_object_call',
    admitted: 'unknown',
    retryable: false,
  });
  const { reports } = await reportFor(error, []);
  const reported = reports[0].error;
  expect(reported).toContain('reason=runtime_replaced');
  expect(reported).toContain('operation=sandbox.exec');
  expect(reported).toContain('phase=durable_object_call');
  expect(reported).toContain('admitted=unknown');
  expect(reported).toContain('retryable=false');
});


test('oversized sensitive SDK phase and operation are discarded before report truncation', async () => {
  const sensitivePhase = 'phase-'.repeat(20);
  const sensitiveOperation = 'operation-'.repeat(12);
  const error = interruptionError('outer failure', new Error('reset detail'), {
    reason: 'runtime_replaced',
    operation: sensitiveOperation,
    phase: sensitivePhase,
    admitted: false,
    retryable: false,
  });
  captureRunnerFailure(error, identity);
  expect(runnerFailureOf(error).interruption).toBe(false);
  const { reports, thrown } = await reportFor(error, [sensitivePhase, sensitiveOperation]);
  const reported = reports[0].error;
  expect(reported).toBe('outer failure');
  expect(reported).not.toContain('phase-');
  expect(reported).not.toContain('operation-');
  expect(thrown.message).toBe(reported);
});


test('an unavailable actor is explicit and never the runner id', async () => {
  const error = interruptionError('outer failure', new Error('reset detail'));
  const reports = [];
  const handle = { async fail(value) { reports.push(value); }, async succeed() { throw new Error('failure fixture cannot succeed'); } };
  let thrown;
  try {
    await withStepNotification({ handle, label: 'script-contracts', command: 'fixture-main', sensitiveValues: [] }, async () => { captureRunnerFailure(error, { ...identity, actor: 'unavailable' }); throw error; }, async (execution) => execution);
  } catch (caught) { thrown = caught; }
  const reported = reports[0].error;
  expect(reported).toContain('actor=unavailable');
  expect(reported).not.toContain(`actor=${identity.runnerId}`);
  expect(thrown.message).toBe(reported);
});
